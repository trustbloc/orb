// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-driver

go 1.16

require (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210817223403-9fb48da0a4b9
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210819195944-a3500e365d5c
	github.com/trustbloc/orb v0.1.3-0.20210813151342-cd05bd36321d
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210817155948-c3cb7a03f63b
)

replace github.com/trustbloc/orb => ../..
