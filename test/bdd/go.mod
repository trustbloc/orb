// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/test/bdd

require (
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/Microsoft/hcsshim v0.8.20 // indirect
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/containerd/containerd v1.5.5 // indirect
	github.com/cucumber/godog v0.9.0
	github.com/cucumber/messages-go/v10 v10.0.3
	github.com/docker/docker v20.10.8+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/uuid v1.3.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210811135743-532e65035d3b
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20210812165607-4eae28b3c74b
	github.com/hyperledger/aries-framework-go-ext/component/storage/mysql v0.0.0-20210714131038-41b5bccef1f9
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210812165607-4eae28b3c74b
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210811170524-6bb150dd7968
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/ipfs/go-ipfs-api v0.2.0
	github.com/jamiealquiza/tachymeter v2.0.0+incompatible
	github.com/klauspost/compress v1.13.4 // indirect
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/mr-tron/base58 v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/tidwall/gjson v1.7.4
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210806163808-39b35274fd3f
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d // indirect
	golang.org/x/sys v0.0.0-20210809222454-d867a43fc93e // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20210811021853-ddbe55d93216 // indirect
	google.golang.org/grpc v1.40.0 // indirect
)

replace github.com/trustbloc/orb => ../../

go 1.16
