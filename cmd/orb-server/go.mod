// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/ThreeDotsLabs/watermill v1.2.0-rc.4
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210909220549-ce3a2ee13e22
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20211001130226-2e3422b613aa
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210929194240-2d601d717a3e
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20211001153855-238da75965f8
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/text v0.3.7 // indirect
)

replace github.com/trustbloc/orb => ../..

go 1.16
