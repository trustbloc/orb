// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/test/bdd

require (
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/containerd/containerd v1.5.5 // indirect
	github.com/cucumber/godog v0.9.0
	github.com/cucumber/messages-go/v10 v10.0.3
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/uuid v1.3.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210813122903-2b268f3c37dd
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20210812165607-4eae28b3c74b
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210813123233-e22ddceee0b1
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210811170524-6bb150dd7968
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/jamiealquiza/tachymeter v2.0.0+incompatible
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/mr-tron/base58 v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/tidwall/gjson v1.7.4
	github.com/trustbloc/orb v0.1.3-0.20210812192933-cce1ed876917
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210813104923-05c0f29c66ae
)

replace github.com/trustbloc/orb => ../../

go 1.16
