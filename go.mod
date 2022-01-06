// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb

require (
	github.com/ThreeDotsLabs/watermill v1.2.0-rc.6
	github.com/ThreeDotsLabs/watermill-amqp v1.1.4-0.20211104161030-4f337d77fb1f
	github.com/ThreeDotsLabs/watermill-http v1.1.3
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/fxamacker/cbor/v2 v2.3.0
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.8-0.20211203093644-b7d189cc06f4
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20211219215001-23cd75276fdc
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210910143505-343c246c837c
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20211206182816-9cdcbcd09dc2
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/mr-tron/base58 v1.2.0
	github.com/multiformats/go-multibase v0.0.3
	github.com/multiformats/go-multihash v0.0.14
	github.com/ory/dockertest/v3 v3.7.0
	github.com/piprate/json-gold v0.4.1-0.20210813112359-33b90c4ca86c
	github.com/prometheus/client_golang v1.11.0
	github.com/rs/cors v1.7.0
	github.com/streadway/amqp v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7
	github.com/trustbloc/sidetree-core-go v0.7.1-0.20211229172717-b542d0074b38
	github.com/trustbloc/vct v0.1.3
	github.com/youmark/pkcs8 v0.0.0-20201027041543-1326539a0a0a // indirect
	go.mongodb.org/mongo-driver v1.8.0
	golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // indirect
	golang.org/x/text v0.3.7 // indirect
)

go 1.16

replace github.com/ThreeDotsLabs/watermill-amqp => github.com/bstasyszyn/watermill-amqp v1.1.4-0.20220106182946-ef499ab8a2f7
