//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
	"github.com/ecojuntak/network-sniffer/internal/config"
	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/ignore"
	"github.com/ecojuntak/network-sniffer/internal/processor"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
	"github.com/ecojuntak/network-sniffer/internal/telemetry"
)

// dedupWindow suppresses repeated identical edges for this long. Each
// processor replica dedups independently, so an edge reported through R
// replicas may be logged up to R times per window.
const dedupWindow = 30 * time.Second

// sweepInterval bounds dedup memory by evicting expired edges periodically.
const sweepInterval = time.Minute

// maxConnectionAgeGrace lets in-flight Report calls finish on a connection
// being recycled by -max-connection-age.
const maxConnectionAgeGrace = 30 * time.Second

func runProcessor(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("processor", flag.ExitOnError)
	configPath := fs.String("config", "", "path to the YAML config file (ignore list, istio); empty disables it")
	listenAddr := fs.String("listen-addr", ":9000", "gRPC listen address for collectors")
	metricsAddr := fs.String("metrics-addr", ":9090", "address for /metrics, /healthz and /readyz")
	// Collector connections are recycled this often so that, behind a plain
	// ClusterIP Service, load spreads to new or restarted replicas.
	maxConnectionAge := fs.Duration("max-connection-age", 5*time.Minute, "recycle collector connections after this long to rebalance replicas")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Ignore list: workload-pair globs whose edges are dropped before emission.
	conf, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	matcher, err := ignore.Compile(conf.Ignore)
	if err != nil {
		return err
	}
	logger.Info("loaded ignore list", slog.Int("rules", len(conf.Ignore)))

	// Kubernetes workload resolver (in-cluster).
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	reg := telemetry.NewRegistry()
	var ready atomic.Bool

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return telemetry.Serve(ctx, *metricsAddr, reg, ready.Load) })

	ctrl := resolver.NewController(cs, logger)
	g.Go(func() error {
		if err := ctrl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("resolver stopped", slog.Any("err", err))
			return err
		}
		return nil
	})

	// Optional Istio ServiceEntry resolver: maps ServiceEntry VIPs (incl. the
	// auto-allocated 240.240.0.0/16 addresses) to their external host. Off
	// unless enabled in config; a failure here (missing CRD/RBAC) degrades
	// ServiceEntry dests back to their IP rather than stopping the processor.
	if conf.Istio.Enabled {
		dc, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return err
		}
		istio := resolver.NewIstioController(dc, ctrl.Cache(), conf.Istio.APIVersion)
		go func() {
			if err := istio.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("istio resolver stopped (ServiceEntry dests will show as IPs)", slog.Any("err", err))
			}
		}()
		logger.Info("istio serviceentry resolution enabled", slog.String("apiVersion", conf.Istio.APIVersion))
	}

	// Records are only accepted once the cache is warm; until then collectors
	// retry and readiness keeps this replica out of the Service.
	select {
	case <-ctx.Done():
		return g.Wait()
	case <-syncDone(ctrl):
	}

	m := processor.NewMetrics(reg)
	deduper := dedup.New(dedupWindow)
	pipeline := processor.NewPipeline(ctrl.Cache(), matcher, deduper, emit.New(os.Stdout), m)

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}
	srv := grpc.NewServer(grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionAge:      *maxConnectionAge,
		MaxConnectionAgeGrace: maxConnectionAgeGrace,
	}))
	snifferv1.RegisterProcessorServiceServer(srv, processor.NewServer(pipeline, m))

	g.Go(func() error { return srv.Serve(lis) })
	g.Go(func() error {
		<-ctx.Done()
		ready.Store(false)
		srv.GracefulStop()
		return nil
	})
	g.Go(func() error {
		sweepLoop(ctx, deduper)
		return nil
	})

	ready.Store(true)
	logger.Info("processor started", slog.String("listen", *listenAddr))
	return g.Wait()
}

// syncDone returns a channel closed once the resolver's informers synced.
func syncDone(ctrl *resolver.Controller) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		ctrl.WaitForSync()
		close(done)
	}()
	return done
}

// sweepLoop periodically evicts expired dedup entries until ctx is cancelled.
func sweepLoop(ctx context.Context, d *dedup.Deduper) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.Sweep(now)
		}
	}
}
