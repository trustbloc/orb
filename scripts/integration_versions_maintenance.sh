#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running orb integration tests protocol versions..."
PWD=`pwd`

export DATABASE_TYPE=mongodb
export DATABASE_URL=mongodb://localhost:27017
export ORB_KMS_ENDPOINT=http://localhost:7878
export CAS_TYPE=local
export COMPOSE_HTTP_TIMEOUT=120
export PGUSER=postgres
export PGPASSWORD=password
export DOCKER_COMPOSE_FILE=docker-compose-testver.yml
export VERSION_TEST=true
export MAINTENANCE_MODE=false

cd test/bdd
go test -tags "testver" -run versions_maintenance -count=1 -v -cover . -p 1 -timeout=30m -race

cd $PWD

