# Spackle build targets. On Windows without make, use .\make.ps1 <target>.

BINARY  := spackle
PKG     := github.com/TMHSDigital/spackle
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)

ifeq ($(OS),Windows_NT)
EXE := .exe
endif

export CGO_ENABLED := 0

.PHONY: all build test test-short test-race lint fmt tidy bench clean help

all: lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)$(EXE) ./cmd/spackle

test:
	go test -shuffle=on ./...

# The fast loop: leaves out the tests that start containers, the full
# benchmark corpus run and the installed-scanner checks.
test-short:
	go test -short -shuffle=on ./...

# The race detector needs cgo, so this target turns it back on.
test-race:
	CGO_ENABLED=1 go test -race -shuffle=on ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -s -w cmd internal

tidy:
	go mod tidy

bench: build
	./$(BINARY)$(EXE) bench --corpus bench/corpus --out bench/results

clean:
	go clean
	rm -rf dist $(BINARY) $(BINARY).exe coverage.out

help:
	@echo "build      Build the spackle binary"
	@echo "test       Run unit tests"
	@echo "test-short Run unit tests without the slow ones (containers, full corpus)"
	@echo "test-race  Run unit tests with the race detector (needs cgo)"
	@echo "lint       go vet and golangci-lint"
	@echo "fmt        gofmt -s"
	@echo "tidy       go mod tidy"
	@echo "bench      Run the benchmark corpus and write bench/results/<date>-<model>.json"
	@echo "clean      Remove build output"
