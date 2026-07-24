//go:build linux

// Package bpf loads the eBPF program, attaches it to the kernel tracepoint and
// streams raw event records from the ring buffer. This file is linux-only; the
// pure pipeline packages that consume its output are platform-independent and
// tested on all platforms.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel sniffer ../../bpf/sniffer.c -- -I../../bpf/headers

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Loader owns the attached eBPF objects and the ring-buffer reader.
type Loader struct {
	objs   snifferObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New removes the memlock limit, loads the compiled objects, attaches the
// tracepoint and the tcp_connect kprobe, and opens the ring buffer.
func New() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs snifferObjects
	if err := loadSnifferObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	var links []link.Link
	closeAll := func() {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleSetState, nil)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}
	links = append(links, tp)

	// fentry on tcp_connect records the connecting task's PID in process
	// context; the tracepoint joins it onto the emitted edge. fentry (not kprobe)
	// keeps the eBPF object arch-neutral. See bpf/sniffer.c.
	fe, err := link.AttachTracing(link.TracingOptions{Program: objs.HandleTcpConnect})
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("attach tcp_connect fentry: %w", err)
	}
	links = append(links, fe)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}

	return &Loader{objs: objs, links: links, reader: rd}, nil
}

// Read blocks until the next raw event record is available and returns its
// bytes. It returns ErrClosed after Close has been called.
func (l *Loader) Read() ([]byte, error) {
	rec, err := l.reader.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		return nil, ErrClosed
	}
	if err != nil {
		return nil, fmt.Errorf("read ringbuf: %w", err)
	}
	return rec.RawSample, nil
}

// Close detaches the program and releases all resources.
func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		errs = append(errs, l.reader.Close())
	}
	for _, l := range l.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, l.objs.Close())
	return errors.Join(errs...)
}
