# The builder deliberately stays on the *build* platform and cross-compiles via
# GOARCH, rather than running under emulation for each target. Go cross-compiles
# natively with CGO disabled, so a multi-arch build costs one compile per arch
# instead of one QEMU-emulated toolchain per arch.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o ocsp-responder ./cmd/ocsp-responder

FROM alpine:3.24
RUN apk --no-cache add ca-certificates && \
    addgroup -S ocsp && adduser -S -G ocsp ocsp && \
    mkdir -p /var/lib/ocsp-responder/acme && \
    chown -R ocsp:ocsp /var/lib/ocsp-responder
COPY --from=builder /build/ocsp-responder /usr/local/bin/

# ACME-issued certificates are persisted here. Declared as a volume so they
# survive a container replacement — without persistence the responder
# re-orders on every restart and hits CA rate limits.
VOLUME ["/var/lib/ocsp-responder"]
USER ocsp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ocsp-responder"]
CMD ["--config", "/etc/ocsp-responder/ocsp-responder.yaml"]
