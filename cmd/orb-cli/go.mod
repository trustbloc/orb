// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-cli

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211203093644-b7d189cc06f4
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210915134807-3e19121646a4
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210901104217-40a48c89b9f7
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/ipfs/go-ipfs-files v0.0.8
	github.com/libp2p/go-libp2p-core v0.8.0
	github.com/multiformats/go-multiaddr v0.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/orb v0.1.3-0.20210914173654-dab098ce4e32
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
)

replace github.com/trustbloc/orb => ../..

go 1.16
