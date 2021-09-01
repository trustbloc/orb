// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-cli

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210816113201-26c0665ef2b9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210901104217-40a48c89b9f7
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210901104217-40a48c89b9f7
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/ipfs/go-ipfs-files v0.0.8
	github.com/libp2p/go-libp2p-core v0.8.0
	github.com/multiformats/go-multiaddr v0.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210819195944-a3500e365d5c
	github.com/trustbloc/orb v0.1.3-0.20210826224204-8f7cf7841ff2
)

replace github.com/trustbloc/orb => ../..

go 1.16
