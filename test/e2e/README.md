# End-to-end test (kind on podman)

Runs the collector and processor on a real kernel in a 3-node kind cluster and
checks the emitted edges, metrics, processor failover and rebalancing.

## Prerequisites

- macOS with podman 5 (applehv), `kind`, `kubectl`, `jq`: `brew install kind`
- About 8GiB of RAM and 60GB of disk for the dedicated podman machine

## Run

```bash
make e2e                 # build, create cluster, test, delete cluster
KEEP=1 make e2e          # keep the cluster for inspection (context kind-sniffer-e2e)
SKIP_BUILD=1 make e2e    # reuse the existing eBPF object and image
make e2e-clean           # delete a kept cluster
```

The first run creates a rootful podman machine named `kind-e2e`. applehv runs
one machine at a time, so the script stops any other running machine
(normally `podman-machine-default`). Switch back with:

```bash
podman machine stop kind-e2e && podman machine start podman-machine-default
```

The eBPF object is generated inside a `golang:1.26-bookworm` container on that
machine, against its kernel's BTF.

## What is checked

| Check | Meaning |
| --- | --- |
| rollout | processor 2/2 ready (cache synced), collector on all 3 nodes incl. control-plane |
| A1 | edge `e2e/caller -> e2e/echo:8080 (http)` emitted |
| A2 | no reversed phantom edge `echo -> caller` |
| A3 | every collector sent records and dropped none |
| A4 | processors report emitted records |
| failover | after deleting a processor pod, delivery continues, nothing dropped, replacement emits the edge |
| rebalance | after scaling to 3 replicas, every replica receives batches (`-max-connection-age=20s`) |

## Kind limitations

- **One shared kernel.** All kind nodes are containers on the same VM, so every
  collector sees every connection in the cluster and each edge is reported once
  per node. Dedup collapses that; the test checks that edges are present, never
  how many times they appear.
- **PID namespaces.** The probe records PIDs from the VM's root PID namespace,
  but a kind pod's `hostPID` is the node container's namespace. Pod-UID
  resolution for host-network sources therefore does not work in kind and is
  not asserted here; it is covered by unit tests.
