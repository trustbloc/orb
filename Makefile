#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# Supported Targets:
#
#   all:                 runs code checks, unit and integration tests
#   checks:              runs code checks (license, lint)
#   unit-test:           runs unit tests
#   bdd-test:            run bdd tests
#   generate-test-keys:  generate tls test keys
#


# Local variables used by makefile
CONTAINER_IDS      = $(shell type docker >/dev/null 2>&1 && docker ps -a -q)
DEV_IMAGES         = $(shell type docker >/dev/null 2>&1 && docker images dev-* -q)
ARCH               = $(shell go env GOARCH)
GO_VER             = 1.17

# defined in github.com/trustbloc/orb/pkg/nodeinfo/metadata.go
METADATA_VAR = OrbVersion=0.1.2

GO_LDFLAGS ?= $(METADATA_VAR:%=-X 'github.com/trustbloc/orb/pkg/nodeinfo.%')

# Namespace for orb node
DOCKER_OUTPUT_NS  ?= ghcr.io
ORB_IMAGE_NAME  ?= trustbloc/orb
ORB_DRIVER_IMAGE_NAME  ?= trustbloc/orb-did-driver

ORB_REST_PATH=cmd/orb-server
ORB_DRIVER_REST_PATH=cmd/orb-driver

# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.15
GO_TAGS    ?=

export GO111MODULE=on

.PHONY: checks
checks: license lint

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: unit-test
unit-test:
	@scripts/unit.sh

.PHONY: all
all: clean checks unit-test bdd-test

.PHONY: orb
orb:
	@mkdir -p ./.build/bin
	@cd ${ORB_REST_PATH} && go build -v -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" \
		-o ../../.build/bin/orb main.go

.PHONY: orb-docker
orb-docker:
	@docker build -f ./images/orb/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ORB_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GO_LDFLAGS="$(GO_LDFLAGS)" \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: orb-driver
orb-driver:
	@echo "Building orb-driver"
	@mkdir -p ./.build/bin
	@cd ${ORB_DRIVER_REST_PATH} && go build -o ../../.build/bin/orb-driver main.go

.PHONY: orb-driver-docker
orb-driver-docker:
	@docker build -f ./images/orb-driver/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ORB_DRIVER_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: clean-images
clean-images:
	@echo "Stopping all containers, pruning containers and images, deleting dev images"
ifneq ($(strip $(CONTAINER_IDS)),)
	@docker stop $(CONTAINER_IDS)
endif
	@docker system prune -f
ifneq ($(strip $(DEV_IMAGES)),)
	@docker rmi $(DEV_IMAGES) -f
endif

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/orb \
		--entrypoint "/opt/workspace/orb/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: build-orb-cli-binaries
build-orb-cli-binaries:
	@echo "Building orb cli binaries"
	@cd cmd/orb-cli/;CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../../.build/dist/bin/orb-cli-linux-amd64 main.go
	@cd .build/dist/bin;tar cvzf orb-cli-linux-amd64.tar.gz orb-cli-linux-amd64;rm -rf orb-cli-linux-amd64
	@cd cmd/orb-cli/;CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../../.build/dist/bin/orb-cli-linux-arm64 main.go
	@cd .build/dist/bin;tar cvzf orb-cli-linux-arm64.tar.gz orb-cli-linux-arm64;rm -rf orb-cli-linux-arm64
	@cd cmd/orb-cli/;CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o ../../.build/dist/bin/orb-cli-darwin-arm64 main.go
	@cd .build/dist/bin;tar cvzf orb-cli-darwin-arm64.tar.gz orb-cli-darwin-arm64;rm -rf orb-cli-darwin-arm64
	@cd cmd/orb-cli/;CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o ../../.build/dist/bin/orb-cli-darwin-amd64 main.go
	@cd .build/dist/bin;tar cvzf orb-cli-darwin-amd64.tar.gz orb-cli-darwin-amd64;rm -rf orb-cli-darwin-amd64
	@for f in .build/dist/bin/orb-cli*; do shasum -a 256 $$f > $$f.sha256; done

.PHONY: extract-orb-cli-binaries
extract-orb-cli-binaries:
	@echo "Extract orb cli binaries"
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf orb-cli-linux-amd64.tar.gz;mv orb-cli-linux-amd64 ../../extract/
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf orb-cli-darwin-amd64.tar.gz;mv orb-cli-darwin-amd64 ../../extract/

.PHONY: bdd-test
bdd-test: generate-test-keys orb-docker orb-driver-docker build-orb-cli-binaries extract-orb-cli-binaries
	@scripts/integration.sh

.PHONY: clean
clean:
	rm -Rf ./.build
	rm -Rf ./test/bdd/docker-compose.log
	rm -Rf ./test/bdd/fixtures/keys/tls
	rm -Rf ./test/bdd/fixtures/data/ipfs
