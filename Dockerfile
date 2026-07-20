# Build the eBPF object + Go binary, then ship a minimal static image.
FROM golang:1.26-bookworm AS build

# eBPF toolchain for `make generate` (clang, llvm, libbpf headers, bpftool).
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm linux-tools-generic ca-certificates curl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .

# Generate eBPF bindings and build a static binary.
RUN go mod tidy \
    && make generate \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sniffer ./cmd/sniffer

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
# The DaemonSet runs the process as root (UID 0) for eBPF capabilities.
USER 0:0
COPY --from=build /out/sniffer /usr/local/bin/sniffer
ENTRYPOINT ["/usr/local/bin/sniffer"]
