GO ?= go
GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
GOTMPDIR ?= $(CURDIR)/.gotmp
GOENV = GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOTMPDIR=$(GOTMPDIR)
GO_RUN = $(GOENV) $(GO)
BIN_DIR ?= $(CURDIR)/bin
IMAGE ?= cis-helper-example
APP ?= fetch-svid

.PHONY: help fmt test build build-fetch-svid build-https-server build-https-client build-examples vendor tidy clean docker-build

help:
	@echo "Available targets:"
	@echo "  fmt                Format Go sources"
	@echo "  test               Run go test ./..."
	@echo "  build              Build the default example binary ($(APP))"
	@echo "  build-fetch-svid   Build cmd/fetch-svid"
	@echo "  build-https-server Build cmd/https-server"
	@echo "  build-https-client Build cmd/https-client"
	@echo "  build-examples     Build all example binaries into ./bin"
	@echo "  vendor             Vendor Go dependencies for offline builds"
	@echo "  tidy               Run go mod tidy"
	@echo "  clean              Remove build output and local Go caches"
	@echo "  docker-build       Build binaries and then package Docker image (IMAGE=$(IMAGE), APP=$(APP))"

fmt:
	$(GO_RUN) fmt ./...

test:
	$(GO_RUN) test ./...

build: | $(BIN_DIR)
	$(GO_RUN) build -o $(BIN_DIR)/$(APP) ./cmd/$(APP)

build-fetch-svid: | $(BIN_DIR)
	$(GO_RUN) build -o $(BIN_DIR)/fetch-svid ./cmd/fetch-svid

build-https-server: | $(BIN_DIR)
	$(GO_RUN) build -o $(BIN_DIR)/https-server ./cmd/https-server

build-https-client: | $(BIN_DIR)
	$(GO_RUN) build -o $(BIN_DIR)/https-client ./cmd/https-client

build-examples: build-fetch-svid build-https-server build-https-client

vendor:
	$(GO_RUN) mod vendor

tidy:
	$(GO_RUN) mod tidy

clean:
	rm -rf $(BIN_DIR) $(GOCACHE) $(GOMODCACHE) $(GOTMPDIR)

docker-build:
	./build.sh
	docker build --build-arg APP=$(APP) -t $(IMAGE) .

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
