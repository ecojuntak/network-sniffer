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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// connObjects are the connection-capture programs and their ring buffer. They
// are loaded on their own (not via the generated snifferObjects) so the DNS
// program — which needs CAP_NET_ADMIN to load — stays optional.
type connObjects struct {
	HandleSetState   *ebpf.Program `ebpf:"handle_set_state"`
	HandleTcpConnect *ebpf.Program `ebpf:"handle_tcp_connect"`
	Events           *ebpf.Map     `ebpf:"events"`
}

func (o *connObjects) Close() error {
	return _SnifferClose(o.HandleSetState, o.HandleTcpConnect, o.Events)
}

// dnsObjects are the DNS-capture program and its ring buffer.
type dnsObjects struct {
	HandleDnsIngress *ebpf.Program `ebpf:"handle_dns_ingress"`
	DnsEvents        *ebpf.Map     `ebpf:"dns_events"`
}

func (o *dnsObjects) Close() error {
	return _SnifferClose(o.HandleDnsIngress, o.DnsEvents)
}

// Loader owns the attached eBPF objects and the ring-buffer readers.
type Loader struct {
	spec   *ebpf.CollectionSpec
	objs   connObjects
	links  []link.Link
	reader *ringbuf.Reader

	dnsObjs   dnsObjects
	dnsReader *ringbuf.Reader
}

// New removes the memlock limit, loads the compiled objects, attaches the
// tracepoint and the tcp_connect kprobe, and opens the ring buffer. DNS
// capture is attached separately with AttachDNS.
func New() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadSniffer()
	if err != nil {
		return nil, err
	}
	l := &Loader{spec: spec}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", l.objs.HandleSetState, nil)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}
	l.links = append(l.links, tp)

	// fentry on tcp_connect records the connecting task's PID in process
	// context; the tracepoint joins it onto the emitted edge. fentry (not kprobe)
	// keeps the eBPF object arch-neutral. See bpf/sniffer.c.
	fe, err := link.AttachTracing(link.TracingOptions{Program: l.objs.HandleTcpConnect})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach tcp_connect fentry: %w", err)
	}
	l.links = append(l.links, fe)

	rd, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	l.reader = rd

	return l, nil
}

// AttachDNS loads the DNS-capture program, attaches it as cgroup_skb ingress
// to the cgroup v2 directory at cgroupPath (the root, so every pod on the node
// is covered) and opens its ring buffer. It needs CAP_NET_ADMIN and a cgroup
// v2 hierarchy. On error the loader is left without DNS capture and ReadDNS
// reports ErrClosed; connection capture is unaffected.
func (l *Loader) AttachDNS(cgroupPath string) error {
	var objs dnsObjects
	if err := l.spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load dns bpf objects: %w", err)
	}
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.HandleDnsIngress,
	})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach cgroup_skb ingress to %s: %w", cgroupPath, err)
	}
	rd, err := ringbuf.NewReader(objs.DnsEvents)
	if err != nil {
		cg.Close()
		objs.Close()
		return fmt.Errorf("open dns ringbuf: %w", err)
	}
	l.dnsObjs = objs
	l.links = append(l.links, cg)
	l.dnsReader = rd
	return nil
}

// Read blocks until the next raw event record is available and returns its
// bytes. It returns ErrClosed after Close has been called.
func (l *Loader) Read() ([]byte, error) {
	return read(l.reader)
}

// ReadDNS blocks until the next raw DNS record is available and returns its
// bytes. It returns ErrClosed after Close has been called, or immediately when
// DNS capture is not attached.
func (l *Loader) ReadDNS() ([]byte, error) {
	if l.dnsReader == nil {
		return nil, ErrClosed
	}
	return read(l.dnsReader)
}

func read(r *ringbuf.Reader) ([]byte, error) {
	rec, err := r.Read()
	if errors.Is(err, ringbuf.ErrClosed) {
		return nil, ErrClosed
	}
	if err != nil {
		return nil, fmt.Errorf("read ringbuf: %w", err)
	}
	return rec.RawSample, nil
}

// Close detaches the programs and releases all resources.
func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		errs = append(errs, l.reader.Close())
	}
	if l.dnsReader != nil {
		errs = append(errs, l.dnsReader.Close())
	}
	for _, l := range l.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, l.objs.Close(), l.dnsObjs.Close())
	return errors.Join(errs...)
}
