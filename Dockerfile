# Multi-arch image. The eBPF object is generated OUTSIDE the image (it needs
# kernel BTF from /sys/kernel/btf, unavailable during a buildx/QEMU build) and
# is present in the build context as internal/bpf/sniffer_bpfel.{go,o}. Run
# `make generate` before building. The bpfel object is endian- (not arch-)
# specific, so the same object serves both linux/amd64 and linux/arm64.
#
# The build stage runs on the BUILD platform (native, no emulation) and
# cross-compiles the Go binary to the TARGET arch via GOARCH — the canonical,
# fast buildx multi-arch pattern. buildx instantiates this stage once per target
# because it depends on the TARGETARCH arg, so each image gets its own arch.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Supplied automatically by buildx per target platform.
ARG TARGETOS
ARG TARGETARCH
RUN test -f internal/bpf/sniffer_bpfel.o \
        || { echo "ERROR: generated eBPF object missing — run 'make generate' first"; exit 1; }
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="-s -w" -o /out/sniffer ./cmd/sniffer

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
# The DaemonSet runs the process as root (UID 0) for eBPF capabilities.
USER 0:0
COPY --from=build /out/sniffer /usr/local/bin/sniffer
ENTRYPOINT ["/usr/local/bin/sniffer"]
