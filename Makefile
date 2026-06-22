.PHONY: build test integration-test coverage coverage-html run lint

build:
	go build ./cmd/ocsp-responder

test:
	go test ./...

integration-test:
	go test -tags integration ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

coverage-html:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

run:
	go run ./cmd/ocsp-responder --config config/ocsp-responder.yaml

lint:
	go vet ./...
