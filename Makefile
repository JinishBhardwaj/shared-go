.PHONY: help test test-cache test-cache-memory test-cache-rediscache test-health test-health-database test-identity test-problem build vet fmt lint

GO_TEST := go test -count=1 -race

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

test: ## Run all package tests
	$(GO_TEST) ./...

test-cache: ## Run cache package tests
	$(GO_TEST) ./cache

test-cache-memory: ## Run cache/memory package tests
	$(GO_TEST) ./cache/memory

test-cache-rediscache: ## Run cache/rediscache package tests
	$(GO_TEST) ./cache/rediscache

test-health: ## Run health package tests
	$(GO_TEST) ./health

test-health-database: ## Run health/database package tests
	$(GO_TEST) ./health/database

test-identity: ## Run identity package tests
	$(GO_TEST) ./identity

test-problem: ## Run problem package tests
	$(GO_TEST) ./problem

build: ## Build all packages
	go build ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Check formatting (gofmt)
	@gofmt -l . | tee /dev/stderr | (! read)

lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...
