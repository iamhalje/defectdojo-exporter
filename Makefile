PKG_PREFIX := github.com/iamhalje/defectdojo-exporter
APP_NAME := defectdojo-exporter

MAKE_CONCURRENCY ?= $(shell getconf _NPROCESSORS_ONLN)
MAKE_PARALLEL := $(MAKE) -j $(MAKE_CONCURRENCY)
DATEINFO_TAG ?= $(shell date -u +'%Y%m%d-%H%M%S')
BUILDINFO_TAG ?= $(shell echo $$(git describe --long --all | tr '/' '-')$$( \
	      git diff-index --quiet HEAD -- || echo '-dirty-'$$(git diff-index -u HEAD | openssl sha1 | cut -d' ' -f2 | cut -c 1-8)))

PKG_TAG ?= $(shell git tag -l --points-at HEAD)
ifeq ($(PKG_TAG),)
PKG_TAG := $(BUILDINFO_TAG)
endif

GO_BUILDINFO = -X '$(PKG_PREFIX)/lib/buildinfo.Version=$(APP_NAME)-$(DATEINFO_TAG)-$(BUILDINFO_TAG)'

GOOS_ARCHES = \
  linux/amd64 \
  linux/arm64 \
  linux/arm \
  linux/ppc64le \
  linux/386 \
  darwin/amd64 \
  darwin/arm64 \
  freebsd/amd64 \
  openbsd/amd64 \
  windows/amd64

# Comma-separated list of target platforms for docker buildx
# Note: docker buildx typically supports linux targets; keep others only if your builder supports them
DOCKER_GOOS_ARCHES ?= linux/amd64,linux/arm64

.PHONY: $(MAKECMDGOALS)

crossbuild:
	$(MAKE_PARALLEL) defectdojo-exporter-crossbuild

build:
	$(MAKE) defectdojo-exporter-pure

clean:
	rm -rf bin/*

defectdojo-exporter-crossbuild: \
	defectdojo-exporter-linux-amd64 \
	defectdojo-exporter-linux-386 \
	defectdojo-exporter-linux-arm64 \
	defectdojo-exporter-linux-arm \
	defectdojo-exporter-linux-ppc64le \
	defectdojo-exporter-darwin-amd64 \
	defectdojo-exporter-darwin-arm64 \
	defectdojo-exporter-freebsd-amd64 \
	defectdojo-exporter-openbsd-amd64 \
	defectdojo-exporter-windows-amd64

defectdojo-exporter-linux-amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-ppc64le:
	CGO_ENABLED=0 GOOS=linux GOARCH=ppc64le $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-s390x:
	CGO_ENABLED=0 GOOS=linux GOARCH=s390x $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-loong64:
	CGO_ENABLED=0 GOOS=linux GOARCH=loong64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-linux-386:
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(MAKE) app-local-goos-goarch

defectdojo-exporter-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-freebsd-amd64:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-openbsd-amd64:
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 $(MAKE) app-local-goos-goarch

defectdojo-exporter-windows-amd64:
	GOARCH=amd64 $(MAKE) app-local-windows-goarch

defectdojo-exporter-pure:
	$(MAKE) app-local-pure

app-local-pure:
	CGO_ENABLED=0 go build -ldflags "$(GO_BUILDINFO)" -o bin/$(APP_NAME)-pure $(PKG_PREFIX)/cmd/

app-local-goos-goarch:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(GO_BUILDINFO)" -o bin/$(APP_NAME)-$(GOOS)-$(GOARCH) $(PKG_PREFIX)/cmd/

app-local-windows-goarch:
	CGO_ENABLED=0 GOOS=windows GOARCH=$(GOARCH) go build -ldflags "$(GO_BUILDINFO)" -o bin/$(APP_NAME)-windows-$(GOARCH).exe $(PKG_PREFIX)/cmd/

docker-crossbuild:
	@for platform in $(GOOS_ARCHES); do \
		GOOS=$${platform%/*}; \
		GOARCH=$${platform#*/}; \
		DOCKER_BUILDKIT=1 docker buildx build \
			--build-arg GOOS=$$GOOS \
			--build-arg GOARCH=$$GOARCH \
			--build-arg APP_NAME=$(APP_NAME) \
			--build-arg PKG_PREFIX=$(PKG_PREFIX) \
			--build-arg GO_BUILDINFO="$(GO_BUILDINFO)" \
			-f Dockerfile.build \
			--output type=local,dest=bin . ; \
	done

docker-build-multiarch-publish:
	DOCKER_BUILDKIT=1 docker buildx build --push\
		--platform $(DOCKER_GOOS_ARCHES) \
		--build-arg APP_NAME=$(APP_NAME) \
		--build-arg PKG_PREFIX=$(PKG_PREFIX) \
		--build-arg GO_BUILDINFO="$(GO_BUILDINFO)" \
		-f Dockerfile \
		-t halje/defectdojo-exporter:latest \
		-t halje/defectdojo-exporter:$(VERSION) \
		.

golangci-lint: install-golangci-lint
	GOEXPERIMENT=synctest golangci-lint run

install-golangci-lint:
	which golangci-lint || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.64.7

remove-golangci-lint:
	rm -rf `which golangci-lint`

govulncheck: install-govulncheck
	govulncheck ./...

install-govulncheck:
	which govulncheck || go install golang.org/x/vuln/cmd/govulncheck@latest

remove-govulncheck:
	rm -rf `which govulncheck`

fmt:
	gofmt -l -w -s ./lib
	gofmt -l -w -s ./cmd

tests:
	GO111MODULE=on go test -race -mod=mod ./...

check-all: tests fmt golangci-lint govulncheck
