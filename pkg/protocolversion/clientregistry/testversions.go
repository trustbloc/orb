//go:build testver
// +build testver

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package clientregistry

import (
	v_test "github.com/trustbloc/orb/pkg/protocolversion/versions/test/v_test/client"
	v1_0 "github.com/trustbloc/orb/pkg/protocolversion/versions/v1_0/client"
)

const (
	// V1_0 ...
	V1_0 = "1.0"

	test = "test"
)

func addVersions(registry *Registry) {
	// register supported versions
	registry.Register(V1_0, v1_0.New())

	// used for test only
	registry.Register(test, v_test.New())
}
