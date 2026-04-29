.PHONY: build test run lint

build:
	go build ./cmd/ocsp-responder

test:
	go test ./...

run:
	go run ./cmd/ocsp-responder --config config/ocsp-responder.yaml

lint:
	go vet ./...
