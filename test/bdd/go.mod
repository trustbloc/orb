// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/test/bdd

require (
	github.com/cucumber/godog v0.9.0
	github.com/cucumber/messages-go/v10 v10.0.3
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210526123422-eec182deab9a
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210426192704-553740e279e5
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210520055214-ae429bb89bf7
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/mr-tron/base58 v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/tidwall/gjson v1.7.4
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210520185648-ad6fce89b352
)

replace github.com/trustbloc/orb => ../../

go 1.16
