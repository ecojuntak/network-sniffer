//go:build linux

// Command sniffer runs the eBPF network sniffer as a node-local daemon. It
// attaches the probe, resolves both ends of each observed connection to their
// kubernetes workloads and logs the resulting service-call edges as JSON.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ecojuntak/network-sniffer/internal/bpf"
	"github.com/ecojuntak/network-sniffer/internal/config"
	"github.com/ecojuntak/network-sniffer/internal/decode"
	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/enrich"
	"github.com/ecojuntak/network-sniffer/internal/ignore"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// procRoot is the procfs mount used for PID->pod resolution. With hostPID the
// container's /proc reflects the host PID namespace, so host PIDs from the
// probe resolve directly.
const procRoot = "/proc"

// dedupWindow suppresses repeated identical edges for this long.
const dedupWindow = 30 * time.Second

// sweepInterval bounds dedup memory by evicting expired edges periodically.
const sweepInterval = time.Minute

func main() {
	configPath := flag.String("config", "", "path to the YAML config file (ignore list); empty disables it")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger, *configPath); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sniffer exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Ignore list: workload-pair globs whose edges are dropped before emission.
	conf, err := config.Load(configPath)
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
	ctrl := resolver.NewController(cs)
	go func() {
		if err := ctrl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("resolver stopped", slog.Any("err", err))
			stop()
		}
	}()

	// Optional Istio ServiceEntry resolver: maps ServiceEntry VIPs (incl. the
	// auto-allocated 240.240.0.0/16 addresses) to their external host. Off
	// unless enabled in config; a failure here (missing CRD/RBAC) degrades
	// ServiceEntry dests back to their IP rather than stopping the sniffer.
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

	// eBPF data source.
	loader, err := bpf.New()
	if err != nil {
		return err
	}
	defer loader.Close()

	// PID-based source resolution: recovers the owning pod for host-network /
	// node-level source traffic (which shares the node IP) from the connecting
	// process's cgroup. Reads the host procfs (DaemonSet runs with hostPID).
	pids := resolver.NewProcResolver(ctrl.Cache(), procRoot)

	// Log pipeline.
	out := emit.New(os.Stdout)
	deduper := dedup.New(dedupWindow)
	go sweepLoop(ctx, deduper)

	// Reading is blocking; close the loader on shutdown to unblock it.
	go func() {
		<-ctx.Done()
		loader.Close()
	}()

	logger.Info("network sniffer started")
	for {
		raw, err := loader.Read()
		if errors.Is(err, bpf.ErrClosed) {
			return ctx.Err()
		}
		if err != nil {
			logger.Warn("read event", slog.Any("err", err))
			continue
		}

		ev, err := decode.Decode(raw)
		if err != nil {
			logger.Warn("decode event", slog.Any("err", err))
			continue
		}

		// Loopback is intra-pod (or host-local) traffic with no cross-workload
		// dependency and no resolvable identity; drop it. Same for AWS-reserved
		// fd00:ec2::/32 endpoints (metadata/DNS/NTP) and link-local addresses
		// (169.254.0.0/16 IMDS incl. 169.254.169.254, fe80::/10): infrastructure,
		// not workloads. IsSelfEdge drops src==dst traffic (host-network pod
		// talking to itself over the node IP, e.g. node-exporter scrapes).
		//
		// HasEphemeralDestPort drops the server-side half of the tracepoint's
		// two-sided capture: that record has the client's ephemeral port as its
		// destination and is a reversed duplicate of the canonical caller->callee
		// edge (which is captured from the client side). See model.go.
		if ev.IsLoopback() || ev.IsSelfEdge() || ev.IsAWSReserved() || ev.IsLinkLocal() || ev.HasEphemeralDestPort() {
			continue
		}

		sc := enrich.Enrich(ev, ctrl.Cache(), pids, ctrl.Cache())
		if matcher.ShouldIgnoreCall(sc) {
			continue
		}
		if deduper.Allow(sc, time.Now()) {
			out.Log(sc)
		}
	}
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
