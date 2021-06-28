#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating orb Test PKI"

# TODO re-use the sandbox CA script https://github.com/trustbloc/orb/issues/131
cd /opt/workspace/orb
mkdir -p test/bdd/fixtures/keys/tls
tmp=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = orb.domain1.com
DNS.3 = orb2.domain1.com
DNS.4 = orb.domain2.com
DNS.5 = orb.domain3.com
DNS.6 = orb.domain4.com" >> "$tmp"

#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bdd/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bdd/fixtures/keys/tls/ec-cacert.pem

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bdd/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:orb/OU=orb/CN=localhost" -out test/bdd/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/ec-key.csr -CA test/bdd/fixtures/keys/tls/ec-cacert.pem -CAkey test/bdd/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -extfile "$tmp" -out test/bdd/fixtures/keys/tls/ec-pubCert.pem -days 365


# generate key pair for recover/updates
mkdir -p test/bdd/fixtures/keys/recover
mkdir -p test/bdd/fixtures/keys/update
mkdir -p test/bdd/fixtures/keys/update2
mkdir -p test/bdd/fixtures/keys/recover2
mkdir -p test/bdd/fixtures/keys/update3

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover/key.pem
openssl ec -in test/bdd/fixtures/keys/recover/key.pem -passout pass:123 -out test/bdd/fixtures/keys/recover/key_encrypted.pem -aes256
openssl ec -in test/bdd/fixtures/keys/recover/key.pem -pubout -out test/bdd/fixtures/keys/recover/public.pem

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/recover2/key.pem
openssl ec -in test/bdd/fixtures/keys/recover2/key.pem -passout pass:123 -out test/bdd/fixtures/keys/recover2/key_encrypted.pem -aes256
openssl ec -in test/bdd/fixtures/keys/recover2/key.pem -pubout -out test/bdd/fixtures/keys/recover2/public.pem

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update/key.pem
openssl ec -in test/bdd/fixtures/keys/update/key.pem -passout pass:123 -out test/bdd/fixtures/keys/update/key_encrypted.pem -aes256
openssl ec -in test/bdd/fixtures/keys/update/key.pem -pubout -out test/bdd/fixtures/keys/update/public.pem

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update2/key.pem
openssl ec -in test/bdd/fixtures/keys/update2/key.pem -passout pass:123 -out test/bdd/fixtures/keys/update2/key_encrypted.pem -aes256
openssl ec -in test/bdd/fixtures/keys/update2/key.pem -pubout -out test/bdd/fixtures/keys/update2/public.pem

openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/update3/key.pem
openssl ec -in test/bdd/fixtures/keys/update3/key.pem -passout pass:123 -out test/bdd/fixtures/keys/update3/key_encrypted.pem -aes256
openssl ec -in test/bdd/fixtures/keys/update3/key.pem -pubout -out test/bdd/fixtures/keys/update3/public.pem

echo "done generating orb PKI"
