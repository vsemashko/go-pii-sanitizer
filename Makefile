.PHONY: help test test-verbose test-coverage coverage coverage-html bench fmt vet lint clean all

# Default target
.DEFAULT_GOAL := help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Package paths
PKG=./sanitizer/...
ALL_PKGS=./...

# Coverage files
COVERAGE_FILE=coverage.out
COVERAGE_HTML=coverage.html

## help: Show this help message
help:
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^## //p' ${MAKEFILE_LIST} | sed -e 's/^/  /'

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v $(PKG)

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	$(GOTEST) -v -count=1 $(PKG)

## test-short: Run tests in short mode (skip long-running tests)
test-short:
	@echo "Running tests in short mode..."
	$(GOTEST) -v -short $(PKG)

## test-coverage: Run tests and generate coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=$(COVERAGE_FILE) -covermode=atomic $(PKG)
	@echo "Coverage report generated: $(COVERAGE_FILE)"

## coverage: Generate and display coverage report
coverage: test-coverage
	@echo "Coverage summary:"
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)

## coverage-html: Generate HTML coverage report and open in browser
coverage-html: test-coverage
	@echo "Generating HTML coverage report..."
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "HTML coverage report generated: $(COVERAGE_HTML)"
	@echo "Opening in browser..."
	@which xdg-open > /dev/null && xdg-open $(COVERAGE_HTML) || \
	which open > /dev/null && open $(COVERAGE_HTML) || \
	echo "Please open $(COVERAGE_HTML) manually in your browser"

## bench: Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem $(PKG)

## bench-verbose: Run benchmarks with verbose output
bench-verbose:
	@echo "Running benchmarks with verbose output..."
	$(GOTEST) -v -bench=. -benchmem -run=^$$ $(PKG)

## bench-cpu: Run CPU benchmarks with profiling
bench-cpu:
	@echo "Running CPU benchmarks with profiling..."
	$(GOTEST) -bench=. -benchmem -cpuprofile=cpu.prof $(PKG)
	@echo "CPU profile generated: cpu.prof"
	@echo "View with: go tool pprof cpu.prof"

## bench-mem: Run memory benchmarks with profiling
bench-mem:
	@echo "Running memory benchmarks with profiling..."
	$(GOTEST) -bench=. -benchmem -memprofile=mem.prof $(PKG)
	@echo "Memory profile generated: mem.prof"
	@echo "View with: go tool pprof mem.prof"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) $(ALL_PKGS)
	@echo "Code formatted successfully"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) $(ALL_PKGS)
	@echo "go vet completed successfully"

## lint: Run golangci-lint (if available)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "Running golangci-lint..."; \
		golangci-lint run $(ALL_PKGS); \
		echo "Linting completed successfully"; \
	else \
		echo "golangci-lint not found. Install it with:"; \
		echo "  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

## tidy: Tidy go.mod and go.sum
tidy:
	@echo "Tidying go.mod and go.sum..."
	$(GOMOD) tidy
	@echo "go.mod and go.sum tidied successfully"

## verify: Verify dependencies
verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify
	@echo "Dependencies verified successfully"

## clean: Clean build artifacts and coverage files
clean:
	@echo "Cleaning build artifacts..."
	$(GOCLEAN)
	rm -f $(COVERAGE_FILE) $(COVERAGE_HTML)
	rm -f *.prof *.test
	@echo "Cleaned successfully"

## all: Run fmt, vet, test, and coverage
all: fmt vet test coverage
	@echo "All checks completed successfully"

## ci: Run all CI checks (fmt, vet, lint, test, coverage)
ci: fmt vet test-coverage
	@echo "CI checks completed successfully"
	@echo "Coverage report:"
	@$(GOCMD) tool cover -func=$(COVERAGE_FILE) | grep total
