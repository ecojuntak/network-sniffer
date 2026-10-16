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
  ──▶ dst IP → hostname (DNS cache)                       │
  ──▶ aggregate (1s) ──▶ batch ──── gRPC ───────▶     resolver cache (IP/UID → workload)
cgroup_skb ingress (UDP sport 53)                         ▲
  ──▶ dns ring buffer ──▶ parse A/AAAA ──▶ DNS cache  k8s informers
```

1. An eBPF program (`bpf/sniffer.c`) attaches to the ABI-stable
   `sock:inet_sock_set_state` tracepoint and emits one fixed-layout record per
   TCP connection reaching `ESTABLISHED` (IPv4 and IPv6).
2. The **collector** (`internal/collector`) decodes each record, orients it
   caller → callee, drops node-local noise, resolves the connecting process's
   pod UID from its cgroup (only possible on the node), looks up the
   destination's hostname in the node's DNS cache (see below), folds repeated
   connections into flow records and ships them in batches over gRPC
   (`api/sniffer/v1`). It holds no Kubernetes state, so its memory does not
   grow with the cluster.
3. The **processor** (`internal/processor`) keeps a cluster-wide
   `IP/UID → workload` cache, populated by client-go informers. A pod is
   resolved to its **top-level owner** (Deployment, StatefulSet, Argo Rollout,
   …) by walking the owner chain. Unknown IPs become `external` peers named by
   their address.
4. `internal/enrich` joins each record with the cache into a `ServiceCall`.
   A destination with no cluster identity is named by the hostname the
   collector attached (e.g. `api.stripe.com`), falling back to its IP.
5. `internal/dedup` collapses repeated identical edges within a time window.
   Each processor replica dedups independently, so an edge may be logged once
   per replica per window.
6. `internal/emit` writes the `ServiceCall` as a structured JSON log line.

### External destination names

A second eBPF program (`cgroup_skb/ingress` on the cgroup v2 root) copies every
UDP packet from source port 53 delivered to any socket on the node, in any pod.
The collector parses the A/AAAA answers (`internal/decode/dns.go`) and keeps an
`IP → hostname` map (`internal/dnscache`). Each entry lives for the record's TTL,
clamped to [1m, 30m]. A CNAME chain is attributed to the name the application
queried. Outbound flows to a cached IP carry the name as `dst_hostname`, and the
processor uses it only when the IP has no cluster identity, so pods, Services,
ServiceEntries and nodes keep their names. All IPs of one host collapse into one
edge.

The feature needs `CAP_NET_ADMIN` and a cgroup v2 hierarchy mounted at
`-cgroup-path` (default `/sys/fs/cgroup`). Without them the collector logs a
warning and reports external destinations by IP. Disable it with
`-dns-names=false`. Limitations:

- DNS over TCP, DoT and DoH are not seen.
- Lookups made before the collector started are not known until the name is
  resolved again.
- `/etc/hosts` entries are not seen.
- One IP serving several names (CDNs, shared load balancers) gets the name
  resolved most recently on that node.

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
| `internal/dnscache`     | all      | Node-local IP → hostname cache from DNS        |
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
