> This project created as part of my learning about eBPF. The code mostly AI generated code.

# Network Sniffer

Network sniffer is an app deployed in a kubernetes cluster as a DaemonSet. It
produces logs of service calls so that a service-dependency map can be built for
all workloads inside and outside of the cluster.

Each observed connection is logged as one JSON line with:

- source workload name
- source workload namespace
- destination workload name
- destination workload namespace
- destination workload port
- destination workload protocol

## Tech

- Golang
- eBPF (CO-RE, `cilium/ebpf`)

## How it works

```
kernel tracepoint            userspace (Go)
sock:inet_sock_set_state ──▶ ring buffer ──▶ decode ──▶ enrich ──▶ dedup ──▶ emit (JSON log)
                                                            │
                                          resolver cache (podIP → workload)
                                                            ▲
                                          k8s informers (pods, replicasets)
```

1. An eBPF program (`bpf/sniffer.c`) attaches to the ABI-stable
   `sock:inet_sock_set_state` tracepoint and emits one fixed-layout record per
   TCP connection reaching `ESTABLISHED` (IPv4 and IPv6).
2. `internal/decode` parses each raw record into a typed `ConnectionEvent`.
3. `internal/resolver` keeps a cluster-wide `podIP → workload` cache, populated
   by client-go informers. A pod is resolved to its **top-level owner**
   (Deployment, StatefulSet, Argo Rollout, …) by walking the owner chain
   (`Pod → ReplicaSet → Deployment/Rollout`). Unknown IPs become `external`
   peers named by their address.
4. `internal/enrich` joins the event with the resolver into a `ServiceCall`.
5. `internal/dedup` collapses repeated identical edges within a time window so a
   busy node does not flood the log.
6. `internal/emit` writes the `ServiceCall` as a structured JSON log line.

## Layout

| Path                    | Platform | Purpose                                        |
| ----------------------- | -------- | ---------------------------------------------- |
| `internal/model`        | all      | Domain types (events, workloads, service call) |
| `internal/decode`       | all      | Raw eBPF record → `ConnectionEvent`            |
| `internal/resolver`     | all\*    | IP→workload cache + owner-chain walk           |
| `internal/enrich`       | all      | Event + resolver → `ServiceCall`               |
| `internal/dedup`        | all      | Time-windowed edge de-duplication              |
| `internal/emit`         | all      | `ServiceCall` → JSON log                       |
| `internal/bpf`          | linux    | eBPF loader (`cilium/ebpf`)                    |
| `bpf/sniffer.c`         | linux    | eBPF CO-RE program                             |
| `cmd/sniffer`           | linux    | Daemon entrypoint / pipeline wiring            |
| `deploy/`               | –        | RBAC + DaemonSet manifests                     |

\* The pure resolver logic is platform-independent and tested everywhere; the
client-go informer wiring is linux-tagged.

The eBPF loader, k8s informer wiring and `main` are `//go:build linux`, so the
whole test suite runs on any platform with **zero external dependencies**. The
external modules (`cilium/ebpf`, `k8s.io/client-go`) are pulled by `go mod tidy`
only in the linux build path.

## Develop

```bash
make test     # go test -race -cover ./internal/...  (works on any OS)
make cover    # coverage report
make vet
```

## Build & deploy (linux)

```bash
make tidy       # resolve linux-only deps
make generate   # compile eBPF C → Go bindings (needs clang + vmlinux.h)
make build      # static linux binary
make docker     # container image
kubectl apply -f deploy/   # RBAC + DaemonSet
```

`make generate` needs a `bpf/vmlinux.h`; generate it on the target kernel with
`make vmlinux` (requires `bpftool` and a kernel built with BTF).

## Requirements

- Linux kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE and
  `CAP_BPF`/`CAP_PERFMON`. On older kernels run the DaemonSet `privileged`.

## Scope / roadmap

- v1 captures established **TCP** connections. UDP flows (no connection state)
  are a follow-up.
