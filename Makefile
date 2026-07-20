# network-sniffer Makefile
#
# The eBPF object is generated with bpf2go and requires clang + libbpf headers
# and a vmlinux.h (BTF) for CO-RE. Those live only in the linux build/CI path;
# the pure Go pipeline builds and tests on any platform.

GO        ?= go
CLANG     ?= clang
BPFTOOL   ?= bpftool
IMAGE     ?= ghcr.io/ecojuntak/network-sniffer
TAG       ?= dev

BPF_DIR      := bpf
HEADERS_DIR  := $(BPF_DIR)/headers
VMLINUX      := $(BPF_DIR)/vmlinux.h

# Pinned libbpf release whose CO-RE headers we vendor for bpf2go.
LIBBPF_VERSION ?= v1.5.0
LIBBPF_RAW     := https://raw.githubusercontent.com/libbpf/libbpf/$(LIBBPF_VERSION)/src
LIBBPF_HEADERS := bpf_helpers.h bpf_helper_defs.h bpf_endian.h bpf_core_read.h

.PHONY: all
all: test build

## test: run unit tests with race detector and coverage (pure packages).
.PHONY: test
test:
	$(GO) test -race -cover ./internal/...

## cover: write and show an HTML coverage report.
.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -func=coverage.out

## vet: static analysis.
.PHONY: vet
vet:
	$(GO) vet ./...

## fmt: format all Go sources.
.PHONY: fmt
fmt:
	gofmt -l -w .

## vmlinux: dump kernel BTF into vmlinux.h (run on the target kernel/CI).
# Use the standalone bpftool binary; the linux-tools-common /usr/bin/bpftool
# wrapper needs a per-kernel package and fails on CI cloud kernels. Write via a
# temp file so a failed dump never leaves a corrupt header behind.
$(VMLINUX):
	@test -r /sys/kernel/btf/vmlinux || { \
		echo "ERROR: /sys/kernel/btf/vmlinux not readable — kernel needs CONFIG_DEBUG_INFO_BTF"; \
		exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX).tmp
	mv $(VMLINUX).tmp $(VMLINUX)

## headers: vendor the pinned libbpf CO-RE headers used by the eBPF program.
.PHONY: headers
headers:
	mkdir -p $(HEADERS_DIR)/bpf
	for h in $(LIBBPF_HEADERS); do \
		curl -fsSL "$(LIBBPF_RAW)/$$h" -o "$(HEADERS_DIR)/bpf/$$h"; \
	done

## generate: compile the eBPF C into Go bindings via bpf2go (linux only).
.PHONY: generate
generate: headers $(VMLINUX)
	CGO_ENABLED=0 GOOS=linux $(GO) generate ./internal/bpf/...

## build: build the linux sniffer binary (requires generate first).
.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux $(GO) build -o bin/sniffer ./cmd/sniffer

## tidy: resolve module dependencies (adds cilium/ebpf + client-go on linux).
.PHONY: tidy
tidy:
	GOOS=linux $(GO) mod tidy

## docker: build the container image.
.PHONY: docker
docker:
	docker build -t $(IMAGE):$(TAG) .

## deploy: apply the daemonset and RBAC to the current kube context.
.PHONY: deploy
deploy:
	kubectl apply -f deploy/

## help: list targets.
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
