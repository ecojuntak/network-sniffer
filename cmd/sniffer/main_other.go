//go:build !linux

// This stub lets the command build on non-linux platforms for local
// development and tooling. The sniffer itself requires linux + eBPF.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "network-sniffer runs only on linux (requires eBPF)")
	os.Exit(1)
}
