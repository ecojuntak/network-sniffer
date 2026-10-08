//go:build linux

// Command sniffer is the eBPF network sniffer. It runs in one of two modes:
//
//	sniffer collector   node-local DaemonSet: attaches the eBPF probe and ships
//	                    pre-aggregated connection records to the processor
//	sniffer processor   central Deployment: holds the cluster-wide workload
//	                    cache, resolves both ends of each connection and logs
//	                    the resulting service-call edges as JSON
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const usage = `usage: sniffer <command> [flags]

commands:
  collector   run the node-local eBPF collector (DaemonSet)
  processor   run the central enrichment processor (Deployment)

Run "sniffer <command> -h" for the command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var run func(ctx context.Context, logger *slog.Logger, args []string) error
	switch os.Args[1] {
	case "collector":
		run = runCollector
	case "processor":
		run = runProcessor
	case "-h", "-help", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(ctx, logger, os.Args[2:]); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sniffer exited with error", slog.String("command", os.Args[1]), slog.Any("err", err))
		os.Exit(1)
	}
}
