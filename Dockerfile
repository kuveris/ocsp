FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o ocsp-responder ./cmd/ocsp-responder

FROM alpine:3.19
RUN apk --no-cache add ca-certificates && \
    addgroup -S ocsp && adduser -S -G ocsp ocsp
COPY --from=builder /build/ocsp-responder /usr/local/bin/
USER ocsp
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ocsp-responder"]
CMD ["--config", "/etc/ocsp-responder/ocsp-responder.yaml"]
