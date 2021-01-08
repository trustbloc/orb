#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

CHECK=$(git diff --name-only HEAD --diff-filter=ACMRTUXB * | grep -v .png$ | grep -v .rst$ | grep -v .git \
  | grep -v .pem$ | grep -v .block$ | grep -v .tx$ | grep -v ^LICENSE$ | grep -v _sk$ \
  | grep -v .key$ | grep -v \\.gen.go$ | grep -v vendor_template/ | grep -v .csr$ | grep -v .srl$ \
  | grep -v .md$  | grep -v .crt$ | grep -v .json$ | grep -v .lock$ | grep -v .toml$ | grep -v vendor/ | grep -v go.mod | grep -v go.sum | grep -v ^build/ | grep -v .pb.go$ \
  | grep -v restapi/ | grep -v models/ | grep -v cmd/orb-server/ | sort -u)

if [[ -z "$CHECK" ]]; then
  CHECK=$(git diff-tree --no-commit-id --name-only --diff-filter=ACMRTUXB -r $(git log -2 \
    --pretty=format:"%h") | grep -v .png$ | grep -v .rst$ | grep -v .git \
    | grep -v .pem$ | grep -v .block$ | grep -v .tx$ | grep -v ^LICENSE$ | grep -v _sk$ \
    | grep -v .key$ | grep -v \\.gen.go$ | grep -v vendor_template/  | grep -v .csr$ | grep -v .srl$ \
    | grep -v restapi/ | grep -v models/ |grep -v .md$  | grep -v .crt$ | grep -v .json$ |grep -v .lock$ | grep -v .toml$ | grep -v vendor/ | grep -v go.mod | grep -v go.sum | grep -v ^build/ | grep -v .pb.go$ | sort -u)
fi

if [[ -z "$CHECK" ]]; then
   exit 0
fi

echo "Checking committed files for Copyright headers ..."
missing=`echo $CHECK | xargs grep -L "Copyright"`
if [ -z "$missing" ]; then
   echo "All files have Copyright headers"
   exit 0
fi
echo "The following files are missing Copyright headers:"
echo "$missing"
echo
exit 1
