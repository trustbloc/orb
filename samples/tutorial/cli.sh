#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

apt-get update
apt-get --assume-yes install jq
apt-get --assume-yes install curl
sleep infinity
