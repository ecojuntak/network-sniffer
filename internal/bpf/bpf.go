package bpf

import "errors"

// ErrClosed is returned by Read once the loader has been closed.
var ErrClosed = errors.New("bpf: loader closed")

// ErrUnsupported is returned by New on non-linux platforms.
var ErrUnsupported = errors.New("bpf: eBPF sniffer is only supported on linux")
