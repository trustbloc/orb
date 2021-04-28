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
GO_VER             = 1.16

# Namespace for orb node
DOCKER_OUTPUT_NS  ?= ghcr.io
ORB_IMAGE_NAME  ?= trustbloc/orb

ORB_REST_PATH=cmd/orb-server

# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.12
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
	@echo "Building orb"
	@mkdir -p ./.build/bin
	@cd ${ORB_REST_PATH} && go build -o ../../.build/bin/orb main.go

.PHONY: orb-docker
orb-docker:
	@docker build -f ./images/orb/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(ORB_IMAGE_NAME):latest \
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

.PHONY: bdd-test
bdd-test: generate-test-keys orb-docker
	@scripts/integration.sh

.PHONY: clean
clean:
	rm -Rf ./.build
	rm -Rf ./test/bdd/docker-compose.log
	rm -Rf ./test/bdd/fixtures/keys/tls
	rm -Rf ./test/bdd/fixtures/data/ipfs