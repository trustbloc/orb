// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/orb/test/bdd

require (
	github.com/cucumber/godog v0.9.0
	github.com/cucumber/messages-go/v10 v10.0.3
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/go-fed/httpsig v1.1.1-0.20201223112313-55836744818e
	github.com/google/uuid v1.2.0
	github.com/mr-tron/base58 v1.2.0
	github.com/sirupsen/logrus v1.7.0
	github.com/tidwall/gjson v1.7.4
	github.com/trustbloc/orb v0.0.0
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210324191759-951b35003134
)

replace github.com/trustbloc/orb => ../../

go 1.16
