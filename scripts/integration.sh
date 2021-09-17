#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running orb integration tests..."
PWD=`pwd`

export DATABASE_TYPE=mongodb
export DATABASE_URL=mongodb://localhost:27017
export ORB_KMS_ENDPOINT=http://localhost:7878
export CAS_TYPE=local
export COMPOSE_HTTP_TIMEOUT=120

cd test/bdd
go test -run all,local_cas -count=1 -v -cover . -p 1 -timeout=20m -race

export CAS_TYPE=ipfs

go test -run all -count=1 -v -cover . -p 1 -timeout=20m -race
cd $PWD

