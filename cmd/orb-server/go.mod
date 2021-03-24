// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/google/tink/go v1.5.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210310014234-cfa8c6d6e2f4
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210306170115-156a24580a5c
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210306170115-156a24580a5c
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210310014234-cfa8c6d6e2f4
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210310014234-cfa8c6d6e2f4
	github.com/piprate/json-gold v0.4.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210324191759-951b35003134
)

replace github.com/trustbloc/orb => ../..

go 1.15
