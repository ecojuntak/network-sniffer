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
	link   link.Link
	reader *ringbuf.Reader
}

// New removes the memlock limit, loads the compiled objects, attaches the
// tracepoint and opens the ring buffer.
func New() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs snifferObjects
	if err := loadSnifferObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleSetState, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}

	return &Loader{objs: objs, link: tp, reader: rd}, nil
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
	if l.link != nil {
		errs = append(errs, l.link.Close())
	}
	errs = append(errs, l.objs.Close())
	return errors.Join(errs...)
}
