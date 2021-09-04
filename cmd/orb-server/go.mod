// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/ThreeDotsLabs/watermill v1.2.0-rc.4
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210816113201-26c0665ef2b9
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210826164831-40568174ea45
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20210903215754-11447fcf4d91
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210812172004-259b50ab3879
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210902194940-97c6f2cded6c
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210819195944-a3500e365d5c
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210819194614-967518c8a4a2
	github.com/trustbloc/vct v0.1.3-0.20210812104204-d8ddd5781928
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
)

replace github.com/trustbloc/orb => ../..

go 1.16
