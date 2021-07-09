// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/ThreeDotsLabs/watermill v1.2.0-rc.4
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210708130136-17663938344d
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210604210836-c2fd1343db18
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210604210836-c2fd1343db18
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210604191029-fce55e13c101
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210604191029-fce55e13c101
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210705132944-5a1274856798
	github.com/trustbloc/vct v0.1.2
)

replace github.com/trustbloc/orb => ../..

go 1.16
