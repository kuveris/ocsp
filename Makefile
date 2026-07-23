IMAGE ?= ghcr.io/kuveris/ocsp:latest
COVERAGE_MIN ?= 88

.PHONY: build test integration-test coverage coverage-check coverage-html run lint check \
        up up-d down dev image help

help:
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build ./cmd/ocsp-responder

image: ## Build the Docker image
	docker build -t $(IMAGE) .

test: ## Run unit tests
	go test -race ./...

integration-test: ## Run integration tests
	go test -race -tags integration ./...

coverage: ## Print a coverage summary
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

coverage-check: ## Fail if coverage drops below COVERAGE_MIN
	go test -race -coverprofile=coverage.out ./...
	./scripts/coverage-check.sh coverage.out $(COVERAGE_MIN)

coverage-html: ## Open the coverage report in a browser
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

lint: ## Vet and lint
	go vet ./...
	golangci-lint run ./...
	golangci-lint run --build-tags=integration ./...

check: ## Full pre-commit gate: vet, lint, tests, coverage
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) integration-test
	$(MAKE) coverage-check

run: ## Run locally against the example config
	go run ./cmd/ocsp-responder --config config/ocsp-responder.yaml

up: ## Start the published image via compose
	docker compose up

up-d: ## Start the published image via compose, detached
	docker compose up -d

down: ## Stop the compose stack
	docker compose down

dev: ## Build locally and start the dev stack
	docker compose -f docker-compose.dev.yaml up --build
