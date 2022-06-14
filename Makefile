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
GOBIN_PATH         = $(abspath .)/build/bin
SWAGGER_VERSION    ?= v0.27.0
SWAGGER_DIR		   = "./test/bdd/fixtures/specs"
SWAGGER_OUTPUT	   = $(SWAGGER_DIR)"/openAPI.yml"

# Namespace for orb node
DOCKER_OUTPUT_NS  ?= ghcr.io
ORB_IMAGE_NAME  ?= trustbloc/orb
ORB_TEST_IMAGE_NAME ?= trustbloc/orb-test
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
checks: license open-api-spec lint

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

.PHONY: orb-test
orb-test:
	@mkdir -p ./.build/bin
	@cd ${ORB_REST_PATH} && go build -v -tags testver -ldflags "$(GO_LDFLAGS)" \
		-o ../../.build/bin/orb-test main.go

.PHONY: orb-docker
orb-docker:
	@docker build -f ./images/orb/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ORB_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GO_LDFLAGS="$(GO_LDFLAGS)" \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: orb-test-docker
orb-test-docker:
	@docker build -f ./images/orb-test/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ORB_TEST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=testver \
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
	@mkdir -p .build/dist/bin
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/orb \
		--entrypoint "/opt/workspace/orb/scripts/build-cli.sh" \
		ghcr.io/gythialy/golang-cross:latest

.PHONY: extract-orb-cli-binaries
extract-orb-cli-binaries:
	@echo "Extract orb cli binaries"
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf orb-cli-linux-amd64.tar.gz;mv orb-cli-linux-amd64 ../../extract/
	@mkdir -p .build/extract;cd .build/dist/bin;tar -zxf orb-cli-darwin-amd64.tar.gz;mv orb-cli-darwin-amd64 ../../extract/

.PHONY: bdd-test
bdd-test: generate-test-keys orb-docker orb-test-docker orb-driver-docker build-orb-cli-binaries extract-orb-cli-binaries
	@scripts/integration.sh

.PHONY: clean
clean:
	rm -Rf ./.build
	rm -Rf ./test/bdd/docker-compose.log
	rm -Rf ./test/bdd/fixtures/keys
	rm -Rf ./test/bdd/fixtures/data
	rm -Rf ./test/bdd/fixtures/mongodbbackup
	rm -Rf ./test/bdd/fixtures/export
	rm -Rf ./test/bdd/fixtures/specs
	rm -Rf ./test/bdd/website
	rm -Rf ./coverage.out

.PHONY: open-api-spec
open-api-spec:
	rm -Rf ./test/bdd/fixtures/specs
	@GOBIN=$(GOBIN_PATH) go install github.com/go-swagger/go-swagger/cmd/swagger@$(SWAGGER_VERSION)
	@echo "Generating Open API spec."
	@mkdir $(SWAGGER_DIR)
	@$(GOBIN_PATH)/swagger generate spec -w ./cmd/orb-server -o $(SWAGGER_OUTPUT) -c github.com/trustbloc/orb
	@echo "Validating generated spec"
	@$(GOBIN_PATH)/swagger validate $(SWAGGER_OUTPUT)
