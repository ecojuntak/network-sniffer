> This project created as part of my learning about eBPF. The code mostly AI generated code.

# Network Sniffer

Network sniffer is an app deployed in a kubernetes cluster as a node-local
eBPF **collector** (DaemonSet) and a central **processor** (Deployment). It
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
node: sniffer collector (DaemonSet)                 sniffer processor (Deployment, N replicas)
sock:inet_sock_set_state                            gRPC ProcessorService.Report
  ──▶ ring buffer ──▶ decode ──▶ canonical            ──▶ enrich ──▶ reversed-dup / ignore
  ──▶ filter (loopback, link-local, ...)              ──▶ dedup ──▶ emit (JSON log)
  ──▶ pid → pod UID (/proc cgroup)                        │
  ──▶ aggregate (1s) ──▶ batch ──── gRPC ───────▶     resolver cache (IP/UID → workload)
                                                          ▲
                                                      k8s informers
```

1. An eBPF program (`bpf/sniffer.c`) attaches to the ABI-stable
   `sock:inet_sock_set_state` tracepoint and emits one fixed-layout record per
   TCP connection reaching `ESTABLISHED` (IPv4 and IPv6).
2. The **collector** (`internal/collector`) decodes each record, orients it
   caller → callee, drops node-local noise, resolves the connecting process's
   pod UID from its cgroup (only possible on the node), folds repeated
   connections into flow records and ships them in batches over gRPC
   (`api/sniffer/v1`). It holds no Kubernetes state, so its memory does not
   grow with the cluster.
3. The **processor** (`internal/processor`) keeps a cluster-wide
   `IP/UID → workload` cache, populated by client-go informers. A pod is
   resolved to its **top-level owner** (Deployment, StatefulSet, Argo Rollout,
   …) by walking the owner chain. Unknown IPs become `external` peers named by
   their address.
4. `internal/enrich` joins each record with the cache into a `ServiceCall`.
5. `internal/dedup` collapses repeated identical edges within a time window.
   Each processor replica dedups independently, so an edge may be logged once
   per replica per window.
6. `internal/emit` writes the `ServiceCall` as a structured JSON log line.

Both modes expose Prometheus metrics, `/healthz` and `/readyz` on `:9090`. The
processor is ready only after its informer cache has synced.

## Layout

| Path                    | Platform | Purpose                                        |
| ----------------------- | -------- | ---------------------------------------------- |
| `internal/model`        | all      | Domain types (events, workloads, service call) |
| `internal/decode`       | all      | Raw eBPF record → `ConnectionEvent`            |
| `internal/resolver`     | all\*    | IP→workload cache + owner-chain walk           |
| `internal/enrich`       | all      | Event + resolver → `ServiceCall`               |
| `internal/dedup`        | all      | Time-windowed edge de-duplication              |
| `internal/emit`         | all      | `ServiceCall` → JSON log                       |
| `internal/collector`    | all      | Node-local aggregate + batch + gRPC send       |
| `internal/processor`    | all      | gRPC server + enrich/dedup/emit pipeline       |
| `internal/telemetry`    | all      | Metrics and health endpoints                   |
| `api/sniffer/v1`        | all      | Collector ↔ processor protobuf / gRPC API      |
| `internal/bpf`          | linux    | eBPF loader (`cilium/ebpf`)                    |
| `bpf/sniffer.c`         | linux    | eBPF CO-RE program                             |
| `cmd/sniffer`           | linux    | `sniffer collector` / `sniffer processor`      |
| `deploy/`               | –        | Collector, processor and RBAC manifests        |

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
make proto    # regenerate api/sniffer/v1 after editing the .proto (needs buf)
```

## Build & deploy (linux)

```bash
make tidy       # resolve linux-only deps
make generate   # compile eBPF C → Go bindings (needs clang + vmlinux.h)
make build      # static linux binary
make docker     # container image
kubectl apply -k deploy/   # RBAC + collector DaemonSet + processor Deployment
```

`make generate` needs a `bpf/vmlinux.h`; generate it on the target kernel with
`make vmlinux` (requires `bpftool` and a kernel built with BTF).

## Requirements

- Linux kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`) for CO-RE and
  `CAP_BPF`/`CAP_PERFMON`. On older kernels run the collector DaemonSet `privileged`.

## Scope / roadmap

- v1 captures established **TCP** connections. UDP flows (no connection state)
  are a follow-up.
