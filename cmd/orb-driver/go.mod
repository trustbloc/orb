// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-driver

go 1.16

require (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210915134807-3e19121646a4
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/orb v0.1.3-0.20210914173654-dab098ce4e32
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20211215084556-11b9bec0b714
)

replace github.com/trustbloc/orb => ../..
