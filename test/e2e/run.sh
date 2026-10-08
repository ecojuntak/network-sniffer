#!/usr/bin/env bash
# End-to-end test: builds the eBPF object and image, starts a 3-node kind
# cluster on a dedicated rootful podman machine, deploys the collector and the
# processor with real traffic and checks emitted edges, metrics, processor
# failover and rebalancing. See test/e2e/README.md.
#
# Env:
#   KEEP=1          keep the kind cluster after the run
#   SKIP_BUILD=1    reuse the existing eBPF object and image
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

MACHINE=kind-e2e
CLUSTER=sniffer-e2e
IMAGE=localhost/network-sniffer:e2e
NS=default
PROCESSOR_SEL=app.kubernetes.io/component=processor
COLLECTOR_SEL=app.kubernetes.io/component=collector
TIMEOUT=${TIMEOUT:-120}

export KIND_EXPERIMENTAL_PROVIDER=podman
export CONTAINER_CONNECTION="${MACHINE}-root"
KCTX="kind-${CLUSTER}"
k() { kubectl --context "$KCTX" "$@"; }

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; dump; exit 1; }

dump() {
	log "diagnostics"
	k get pods -A -o wide || true
	k logs -n "$NS" -l "$COLLECTOR_SEL" --tail=50 --prefix || true
	k logs -n "$NS" -l "$PROCESSOR_SEL" --tail=50 --prefix || true
}

cleanup() {
	if [[ "${KEEP:-0}" != 1 ]]; then
		log "deleting kind cluster (KEEP=1 to keep it)"
		kind delete cluster --name "$CLUSTER" || true
	fi
	log "machine '$MACHINE' left running; switch back with:"
	echo "    podman machine stop $MACHINE && podman machine start podman-machine-default"
}

# wait_for <desc> <timeout-seconds> <cmd...>: retry cmd every 3s until it
# succeeds or the timeout elapses.
wait_for() {
	local desc=$1 timeout=$2
	shift 2
	local deadline=$((SECONDS + timeout))
	until "$@" >/dev/null 2>&1; do
		if ((SECONDS >= deadline)); then
			fail "$desc (timed out after ${timeout}s)"
		fi
		sleep 3
	done
	pass "$desc"
}

# metric <pod> <name> [label-substring]: sum of all samples of a metric on a
# pod, read through the API server pod proxy (the images have no shell).
metric() {
	local pod=$1 name=$2 label=${3:-}
	k get --raw "/api/v1/namespaces/${NS}/pods/${pod}:9090/proxy/metrics" |
		awk -v n="$name" -v l="$label" '
			$1 ~ "^"n"([{]|$)" && index($1, l) { s += $2 }
			END { printf "%d\n", s }'
}

pods() { k get pods -n "$NS" -l "$1" -o jsonpath='{.items[*].metadata.name}'; }

# processor_logs [pod]: service_call JSON lines of one or every processor.
processor_logs() {
	if [[ $# -gt 0 ]]; then
		k logs -n "$NS" "$1"
	else
		k logs -n "$NS" -l "$PROCESSOR_SEL" --tail=-1 --prefix=false
	fi | grep '"msg":"service_call"' || true
}

has_edge() {
	processor_logs "$@" | jq -e -s '
		any(.[]; .source_workload == "caller" and .source_namespace == "e2e"
			and .dest_workload == "echo" and .dest_namespace == "e2e"
			and .dest_port == 8080 and .dest_app_protocol == "http")' >/dev/null
}

has_reversed_edge() {
	processor_logs | jq -e -s '
		any(.[]; .source_workload == "echo" and .dest_workload == "caller")' >/dev/null
}

# every_pod <selector> <metric> <op> <value> [label]: metric comparison holds
# on every pod matching selector.
every_pod() {
	local sel=$1 name=$2 op=$3 want=$4 label=${5:-} pod v
	for pod in $(pods "$sel"); do
		v=$(metric "$pod" "$name" "$label")
		test "$v" "$op" "$want" || return 1
	done
}

sum_pods() {
	local sel=$1 name=$2 label=${3:-} pod total=0
	for pod in $(pods "$sel"); do
		total=$((total + $(metric "$pod" "$name" "$label")))
	done
	echo "$total"
}

# --- 1. preflight -----------------------------------------------------------
log "preflight"
for bin in podman kind kubectl jq; do
	command -v "$bin" >/dev/null || { echo "missing '$bin' (brew install $bin)"; exit 1; }
done

if ! podman machine inspect "$MACHINE" >/dev/null 2>&1; then
	log "creating podman machine '$MACHINE' (rootful, 4 CPU, 8GiB)"
	podman machine init "$MACHINE" --rootful --cpus 4 --memory 8192 --disk-size 60
fi
state=$(podman machine inspect "$MACHINE" --format '{{.State}}')
if [[ "$state" != running ]]; then
	# applehv runs one machine at a time.
	for m in $(podman machine list --format '{{.Name}} {{.Running}}' | awk '$2 == "true" { sub(/\*$/, "", $1); print $1 }'); do
		log "stopping podman machine '$m'"
		podman machine stop "$m"
	done
	podman machine start "$MACHINE"
fi
podman machine ssh "$MACHINE" test -r /sys/kernel/btf/vmlinux ||
	{ echo "machine kernel has no BTF (/sys/kernel/btf/vmlinux)"; exit 1; }
podman machine ssh "$MACHINE" test -d /sys/kernel/tracing/events ||
	{ echo "tracefs not mounted at /sys/kernel/tracing on the machine"; exit 1; }
pass "podman machine '$MACHINE' ready ($(podman machine ssh "$MACHINE" uname -r))"

# --- 2. eBPF object ---------------------------------------------------------
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
	if [[ internal/bpf/sniffer_bpfel.o -nt bpf/sniffer.c ]]; then
		log "eBPF object up to date"
	else
		log "generating eBPF object in a builder container"
		podman run --rm --privileged -v "$ROOT:/src" -w /src golang:1.26-bookworm bash -c '
			set -e
			apt-get update -qq
			apt-get install -y -qq clang llvm bpftool make curl >/dev/null
			make generate BPFTOOL=bpftool'
	fi

	# --- 3. image -----------------------------------------------------------
	log "building $IMAGE"
	podman build -t "$IMAGE" .
fi

# --- 4. cluster -------------------------------------------------------------
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
	log "creating kind cluster '$CLUSTER'"
	kind create cluster --name "$CLUSTER" --config test/e2e/kind.yaml --wait 120s
fi
trap cleanup EXIT

log "loading image into kind"
tmpdir=$(mktemp -d)
podman save -o "$tmpdir/image.tar" "$IMAGE"
kind load image-archive "$tmpdir/image.tar" --name "$CLUSTER"
rm -rf "$tmpdir"

# --- 5. deploy --------------------------------------------------------------
log "deploying"
k apply -k test/e2e/
# Pick up a rebuilt image on reruns against a kept cluster.
k rollout restart -n "$NS" daemonset/network-sniffer-collector deployment/network-sniffer-processor
k rollout status -n "$NS" deployment/network-sniffer-processor --timeout="${TIMEOUT}s" ||
	fail "processor rollout"
pass "processor 2/2 ready (informer cache synced)"
k rollout status -n "$NS" daemonset/network-sniffer-collector --timeout="${TIMEOUT}s" ||
	fail "collector rollout"
desired=$(k get ds -n "$NS" network-sniffer-collector -o jsonpath='{.status.desiredNumberScheduled}')
[[ "$desired" == 3 ]] || fail "collector scheduled on $desired nodes, want 3 (control-plane toleration)"
pass "collector running on all 3 nodes"
k rollout status -n e2e deployment/echo --timeout="${TIMEOUT}s" || fail "echo rollout"
k rollout status -n e2e deployment/caller --timeout="${TIMEOUT}s" || fail "caller rollout"

# --- 6. assertions ----------------------------------------------------------
wait_for "A1 edge caller -> echo:8080 (http) emitted" 90 has_edge
if has_reversed_edge; then fail "A2 reversed phantom edge echo -> caller emitted"; fi
pass "A2 no reversed phantom edge"
wait_for "A3 every collector sent records" 60 \
	every_pod "$COLLECTOR_SEL" sniffer_collector_records_sent_total -gt 0
every_pod "$COLLECTOR_SEL" sniffer_collector_records_dropped_total -eq 0 ||
	fail "A3 collectors dropped records"
pass "A3 no collector dropped records"
[[ $(sum_pods "$PROCESSOR_SEL" sniffer_processor_records_total 'result="emitted"') -gt 0 ]] ||
	fail "A4 processor emitted metric is zero"
pass "A4 processors report emitted records"

# --- 7. failover ------------------------------------------------------------
log "failover: deleting one processor pod"
before=$(sum_pods "$COLLECTOR_SEL" sniffer_collector_records_sent_total)
victim=$(pods "$PROCESSOR_SEL" | awk '{ print $1 }')
k delete pod -n "$NS" "$victim" --wait=true
k rollout status -n "$NS" deployment/network-sniffer-processor --timeout="${TIMEOUT}s" ||
	fail "processor did not recover"
newpod=$(k get pods -n "$NS" -l "$PROCESSOR_SEL" --sort-by=.metadata.creationTimestamp \
	-o jsonpath='{.items[-1:].metadata.name}')
sent_increased() { [[ $(sum_pods "$COLLECTOR_SEL" sniffer_collector_records_sent_total) -gt $before ]]; }
wait_for "collectors keep delivering after failover" 60 sent_increased
every_pod "$COLLECTOR_SEL" sniffer_collector_records_dropped_total -eq 0 ||
	fail "collectors dropped records during failover"
pass "no records dropped during failover"
wait_for "replacement processor $newpod emits caller -> echo" 90 has_edge "$newpod"

# --- 8. rebalance -----------------------------------------------------------
log "rebalance: scaling processor to 3"
k scale -n "$NS" deployment/network-sniffer-processor --replicas=3
k rollout status -n "$NS" deployment/network-sniffer-processor --timeout="${TIMEOUT}s" ||
	fail "processor scale-up"
# -max-connection-age=20s in the e2e overlay: within ~2 ages every collector
# has reconnected at least once and the new replica receives batches.
wait_for "every processor replica receives batches" 120 \
	every_pod "$PROCESSOR_SEL" sniffer_processor_batches_total -gt 0

log "all e2e checks passed"
