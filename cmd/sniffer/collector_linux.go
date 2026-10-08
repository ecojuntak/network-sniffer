//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	snifferv1 "github.com/ecojuntak/network-sniffer/api/sniffer/v1"
	"github.com/ecojuntak/network-sniffer/internal/bpf"
	"github.com/ecojuntak/network-sniffer/internal/collector"
	"github.com/ecojuntak/network-sniffer/internal/telemetry"
)

// procRoot is the procfs mount used for PID->pod resolution. With hostPID the
// container's /proc reflects the host PID namespace, so host PIDs from the
// probe resolve directly.
const procRoot = "/proc"

func runCollector(ctx context.Context, logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("collector", flag.ExitOnError)
	processorAddr := fs.String("processor-addr", "network-sniffer-processor:9000", "processor gRPC address (host:port)")
	nodeName := fs.String("node-name", os.Getenv("NODE_NAME"), "name of this node (defaults to $NODE_NAME)")
	metricsAddr := fs.String("metrics-addr", ":9090", "address for /metrics, /healthz and /readyz")
	flushInterval := fs.Duration("flush-interval", time.Second, "how often aggregated flows are sent")
	maxBatch := fs.Int("max-batch", 1000, "maximum records per Report call")
	queueSize := fs.Int("queue-size", 100, "batches buffered while the processor is unreachable")
	reportTimeout := fs.Duration("report-timeout", 5*time.Second, "timeout of one Report call")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *maxBatch <= 0 || *queueSize <= 0 || *flushInterval <= 0 {
		return errors.New("max-batch, queue-size and flush-interval must be positive")
	}
	logger = logger.With(slog.String("node", *nodeName))

	// The connection is lazy: the collector starts capturing immediately and
	// buffers while the processor is unreachable.
	conn, err := grpc.NewClient(*processorAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	reg := telemetry.NewRegistry()
	m := collector.NewMetrics(reg)
	sender := collector.NewSender(snifferv1.NewProcessorServiceClient(conn), *nodeName, *queueSize, *reportTimeout, logger, m)
	coll := collector.New(collector.Config{
		ProcRoot:      procRoot,
		FlushInterval: *flushInterval,
		MaxBatch:      *maxBatch,
	}, sender, logger, m)

	loader, err := bpf.New()
	if err != nil {
		return err
	}
	defer loader.Close()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return telemetry.Serve(ctx, *metricsAddr, reg, nil) })
	g.Go(func() error { return sender.Run(ctx) })
	g.Go(func() error {
		// Reading is blocking; close the loader on shutdown to unblock it.
		<-ctx.Done()
		return loader.Close()
	})
	g.Go(func() error { return coll.Run(ctx, loader) })

	logger.Info("collector started", slog.String("processor", *processorAddr))
	return g.Wait()
}
