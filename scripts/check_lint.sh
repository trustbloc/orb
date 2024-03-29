#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.54.2"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi

echo "Linting pkg"
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run --timeout 10m
echo "Linting orb-server"
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/orb-server ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml --timeout 10m
echo "Linting orb-cli"
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/orb-cli ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml --timeout 10m
echo "Linting orb-driver"
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/orb-driver ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml --timeout 10m
