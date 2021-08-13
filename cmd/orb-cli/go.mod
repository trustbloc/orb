// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/cmd/orb-cli

require (
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210811135743-532e65035d3b
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210813123233-e22ddceee0b1
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210813115605-bcae6a85979c
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/ipfs/go-ipfs-files v0.0.8
	github.com/libp2p/go-libp2p-core v0.8.0
	github.com/multiformats/go-multiaddr v0.3.1 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210812092729-6c61997fa9dd
	github.com/trustbloc/orb v0.1.3-0.20210812192933-cce1ed876917
)

replace github.com/trustbloc/orb => ../..

go 1.16
