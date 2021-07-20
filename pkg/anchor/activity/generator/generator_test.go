/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package generator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testNS  = "did:orb"
	testVer = uint64(1)
)

func TestCreateGenerator(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		gen, err := CreateGenerator(testNS, testVer)
		require.NoError(t, err)
		require.Equal(t, "https://w3id.org/orb#v1", gen)
	})

	t.Run("error - generator not defined for namespace", func(t *testing.T) {
		gen, err := CreateGenerator("did:something", testVer)
		require.Error(t, err)
		require.Empty(t, gen)
		require.Contains(t, err.Error(), "generator not defined for namespace: did:something")
	})
}

func TestParseNamespaceAndVersion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ns, ver, err := ParseNamespaceAndVersion("https://w3id.org/orb#v1")
		require.NoError(t, err)
		require.Equal(t, testVer, ver)
		require.Equal(t, testNS, ns)
	})

	t.Run("error - namespace not defined for generator", func(t *testing.T) {
		ns, ver, err := ParseNamespaceAndVersion("https://w3id.org/other#v1")
		require.Error(t, err)
		require.Zero(t, ver)
		require.Empty(t, ns)
		require.Contains(t, err.Error(), "namespace not defined for generator[https://w3id.org/other#v1]")
	})

	t.Run("error - invalid number of parts in generator", func(t *testing.T) {
		ns, ver, err := ParseNamespaceAndVersion("https://w3id.org/other")
		require.Error(t, err)
		require.Zero(t, ver)
		require.Empty(t, ns)
		require.Contains(t, err.Error(), "invalid namespace and version format")
	})

	t.Run("error - version has to be an integer", func(t *testing.T) {
		ns, ver, err := ParseNamespaceAndVersion("https://w3id.org/orb#vabc")
		require.Error(t, err)
		require.Zero(t, ver)
		require.Empty(t, ns)
		require.Contains(t, err.Error(), "version has to be an integer")
	})
}
