// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-server

require (
	github.com/google/tink/go v1.5.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210223185118-1d6fb5f95ad4
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201119153638-fc5d5e680587
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20201119153638-fc5d5e680587
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.1.6-0.20210223184536-814c6b81a886
)

replace github.com/trustbloc/orb => ../..

go 1.15
