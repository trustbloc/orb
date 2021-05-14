// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210514172045-dfb48754097a
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210426192704-553740e279e5
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210331105523-60637a465684
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210422133815-2ef2d99cb692
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210426170825-9321eebd7637
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210324191759-951b35003134
	golang.org/x/net v0.0.0-20210423184538-5f58ad60dda6 // indirect
)

replace github.com/trustbloc/orb => ../..

go 1.16
