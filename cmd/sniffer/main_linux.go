//go:build linux

// Command sniffer runs the eBPF network sniffer as a node-local daemon. It
// attaches the probe, resolves both ends of each observed connection to their
// kubernetes workloads and logs the resulting service-call edges as JSON.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/ecojuntak/network-sniffer/internal/bpf"
	"github.com/ecojuntak/network-sniffer/internal/decode"
	"github.com/ecojuntak/network-sniffer/internal/dedup"
	"github.com/ecojuntak/network-sniffer/internal/emit"
	"github.com/ecojuntak/network-sniffer/internal/enrich"
	"github.com/ecojuntak/network-sniffer/internal/resolver"
)

// dedupWindow suppresses repeated identical edges for this long.
const dedupWindow = 30 * time.Second

// sweepInterval bounds dedup memory by evicting expired edges periodically.
const sweepInterval = time.Minute

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sniffer exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	// eBPF data source.
	loader, err := bpf.New()
	if err != nil {
		return err
	}
	defer loader.Close()

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
		// fd00:ec2::/32 endpoints (metadata/DNS/NTP): infrastructure, not workloads.
		if ev.IsLoopback() || ev.IsAWSReserved() {
			continue
		}

		sc := enrich.Enrich(ev, ctrl.Cache())
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
