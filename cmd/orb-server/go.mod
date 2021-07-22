// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/ThreeDotsLabs/watermill v1.2.0-rc.4
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210716143947-10d84642fa12
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210716143947-10d84642fa12
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210716143947-10d84642fa12
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210527163745-994ae929f957
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210722141654-ccdb0a1c974d
	github.com/trustbloc/vct v0.1.3-0.20210716152918-7cf3e85adf72
)

replace github.com/trustbloc/orb => ../..

go 1.16
