.PHONY: run build clean docker
# =============================================================================
# Variables
# =============================================================================

# Version stamping
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG        := github.com/tlsentinel/tlsentinel-scanner/internal/version
LDFLAGS    := -ldflags "-X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildTime=$(BUILD_TIME)"

# Directories / commands
BIN_DIR     := bin
CMD := ./cmd/scanner

# Cross-compilation targets (local build)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Container images
IMAGE_REPO := tlsentinel

# =============================================================================
# Local Build (requires Go)
# =============================================================================

define cross_compile
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		ext=$$([ "$$os" = "windows" ] && echo ".exe" || echo ""); \
		echo "  Building $(1) for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(LDFLAGS) \
			-o $(BIN_DIR)/$(1)_$${os}_$${arch}$${ext} $(2) || exit 1; \
	done
endef

run: 
	go run $(LDFLAGS) $(CMD)

build:
	$(call cross_compile,server,$(CMD))

# =============================================================================
# Container Images
# =============================================================================
# Builds production images tagged :VERSION and :latest.
# Override IMAGE_REPO for a registry push, e.g.:
#   make docker-images IMAGE_REPO=ghcr.io/yourorg/tlsentinel

docker:
	docker build -f Dockerfile \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(IMAGE_REPO)/tlsentinel-scanner:$(VERSION) \
		-t $(IMAGE_REPO)/tlsentinel-scanner:latest \
		.

# =============================================================================
# Maintenance
# =============================================================================

clean:
	rm -rf $(BIN_DIR)