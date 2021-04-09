#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

GOBIN_PATH=$(pwd)/.build/bin
ADMIN_SERVER=:8090
CREATE_TREE="$GOBIN_PATH/createtree --admin_server=$ADMIN_SERVER"

GOBIN=$GOBIN_PATH go install github.com/google/trillian/cmd/createtree@v1.3.13 &> /dev/null

MAX_RETRIES=15
RETRY_COUNT=0
until [ $RETRY_COUNT -ge $((MAX_RETRIES-1)) ]
do
   $(eval $CREATE_TREE &> /dev/null) && break
   RETRY_COUNT=$((RETRY_COUNT+1))
   sleep 3
done

eval $CREATE_TREE