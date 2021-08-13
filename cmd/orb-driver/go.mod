// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-driver

go 1.16

require (
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210813123233-e22ddceee0b1
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210812092729-6c61997fa9dd
	github.com/trustbloc/orb v0.1.3-0.20210812192933-cce1ed876917
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210813104923-05c0f29c66ae
)

replace github.com/trustbloc/orb => ../..
