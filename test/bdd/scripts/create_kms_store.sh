#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

KMS_ENDPOINT="http://localhost:7878"

MAX_RETRIES=15
RETRY_COUNT=0
until [ $RETRY_COUNT -ge $((MAX_RETRIES-1)) ]
do
   KMS_STORE_ENDPOINT=$(curl --request POST ${KMS_ENDPOINT}'/kms/keystores' -s -D - --data-raw '{"controller":"controller"}' | grep Location | sed -r 's/Location: //')
   [ ! -z "$KMS_STORE_ENDPOINT" ] && break
   RETRY_COUNT=$((RETRY_COUNT+1))
   sleep 3
done

echo $KMS_STORE_ENDPOINT