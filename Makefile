# SweeTTY build and verification tasks.
# Run `make` or `make help` for the list.

BINARY := sweetty
PKG := ./...
GOFILES := $(shell find . -name '*.go' -not -path './vendor/*')

.DEFAULT_GOAL := help

.PHONY: help build run test vet fmt fmt-check check tidy hooks clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build the sweetty binary
	go build -o $(BINARY) ./cmd/sweetty

run: build ## Build and run (loads ./config.json)
	./$(BINARY)

test: ## Run all tests
	go test $(PKG)

vet: ## Run go vet
	go vet $(PKG)

fmt: ## Format all Go files in place
	gofmt -w $(GOFILES)

fmt-check: ## Fail if any Go file is not gofmt-clean
	@out=$$(gofmt -l $(GOFILES)); \
		if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

check: fmt-check vet build test ## The gate before committing: fmt-check + vet + build + test

hooks: ## Install the tracked git hooks (blocks AI attribution in commit messages)
	git config core.hooksPath .githooks

tidy: ## Tidy go.mod / go.sum
	go mod tidy

clean: ## Remove build artifacts
	rm -f $(BINARY) coverage.out
	rm -rf dist
