// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-driver

go 1.16

require (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210630213923-56e7e13e604b
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210527163745-994ae929f957
	github.com/trustbloc/orb v0.1.2-0.20210630053623-2436c6c2da6a
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210806163808-39b35274fd3f
)

replace github.com/trustbloc/orb => ../..
