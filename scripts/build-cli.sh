#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e



cd /opt/workspace/orb

echo "Building orb cli binaries"

cd cmd/orb-cli/;CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ../../.build/dist/bin/orb-cli-linux-amd64 main.go
cd /opt/workspace/orb
cd .build/dist/bin;tar cvzf orb-cli-linux-amd64.tar.gz orb-cli-linux-amd64;rm -rf orb-cli-linux-amd64
cd /opt/workspace/orb


cd cmd/orb-cli/;CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o ../../.build/dist/bin/orb-cli-linux-arm64 main.go
cd /opt/workspace/orb
cd .build/dist/bin;tar cvzf orb-cli-linux-arm64.tar.gz orb-cli-linux-arm64;rm -rf orb-cli-linux-arm64
cd /opt/workspace/orb


cd cmd/orb-cli/;CC=aarch64-apple-darwin20.2-clang CXX=aarch64-apple-darwin20.2-clang++ CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o ../../.build/dist/bin/orb-cli-darwin-arm64 main.go
cd /opt/workspace/orb
cd .build/dist/bin;tar cvzf orb-cli-darwin-arm64.tar.gz orb-cli-darwin-arm64;rm -rf orb-cli-darwin-arm64
cd /opt/workspace/orb

cd cmd/orb-cli/;CC=o64-clang CXX=o64-clang++ CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o ../../.build/dist/bin/orb-cli-darwin-amd64 main.go
cd /opt/workspace/orb
cd .build/dist/bin;tar cvzf orb-cli-darwin-amd64.tar.gz orb-cli-darwin-amd64;rm -rf orb-cli-darwin-amd64
cd /opt/workspace/orb
