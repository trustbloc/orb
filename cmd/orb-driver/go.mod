// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-driver

go 1.16

require (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210616174319-68cbb4779749
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	github.com/trustbloc/orb v0.1.2-0.20210609211752-6b2a1f8d7f21
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210609181621-184650803827
)

replace github.com/trustbloc/orb => ../..
