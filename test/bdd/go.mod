// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/test/bdd

require (
	github.com/cenkalti/backoff/v4 v4.1.0
	github.com/cucumber/godog v0.9.0
	github.com/cucumber/messages-go/v10 v10.0.3
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210708130136-17663938344d
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210604210836-c2fd1343db18
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210604210836-c2fd1343db18
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210604191029-fce55e13c101
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210604191029-fce55e13c101
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/mr-tron/base58 v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/tidwall/gjson v1.7.4
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210705132944-5a1274856798
)

replace github.com/trustbloc/orb => ../../

go 1.16
