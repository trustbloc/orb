/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/controller/command"
)

func TestNew(t *testing.T) {
	v := New()
	require.NotNil(t, v)
}

func TestLogVerifier_GetRootHashFromEntries(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		v := New()

		entries := []*command.LeafEntry{{
			LeafInput: []byte("leafInput"),
		}}

		sth, err := v.GetRootHashFromEntries(entries)
		require.NoError(t, err)
		require.NotNil(t, sth)
	})
}

func TestLogVerifier_VerifyConsistencyProof(t *testing.T) {
	t.Run("success - first snapshot is zero", func(t *testing.T) {
		v := New()

		var sth0Response command.GetSTHResponse
		err := json.Unmarshal([]byte(sth0), &sth0Response)
		require.NoError(t, err)

		var sth4Response command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sth4Response)
		require.NoError(t, err)

		err = v.VerifyConsistencyProof(
			int64(sth0Response.TreeSize),
			int64(sth4Response.TreeSize),
			sth0Response.SHA256RootHash,
			sth4Response.SHA256RootHash,
			nil)
		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		v := New()

		var sth4Response command.GetSTHResponse
		err := json.Unmarshal([]byte(sth4), &sth4Response)
		require.NoError(t, err)

		var sth5Response command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sth5Response)
		require.NoError(t, err)

		err = v.VerifyConsistencyProof(
			int64(sth4Response.TreeSize),
			int64(sth5Response.TreeSize),
			sth4Response.SHA256RootHash,
			sth5Response.SHA256RootHash,
			nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty proof")
	})
}

var sth0 = `{
  "tree_size": 0,
  "timestamp": 1647375563852,
  "sha256_root_hash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiIySWhVNzUwQlkxWG5tY1A4OHlONlViZG1NaEhLMjdORWxHU0l0V2ZoNFV4Z2Z3WWhXTm8yYVVSSjk2Q3JsOWs3T09Ddm9zamxtME9rR2kwTjlVODJ5UT09In0="
}`

var sth4 = `{
  "tree_size": 4,
  "timestamp": 1647375715221,
  "sha256_root_hash": "GNW0EPlQ+QoKh76QtVqlM3HazFNndRLMolw3P4Ag510=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiIyWVh4NHZxalZhSTdFMGhKdnhldW1mYXBwRU9RZWU2Qm51Wmc0WmNXM2JqdlF6ZGd5bmtsVVNZYm9DbFkreDNiRXFXSXlGdEtVaE9UUjMxckpwbXpDdz09In0="
}`

var sth5 = `{
  "tree_size": 5,
  "timestamp": 1647375720248,
  "sha256_root_hash": "F662myG5fHA2ASVuWBfBLWxGZWgLz1LaB0Cl1GDKGOg=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiJtSGVlUXRpNTh4UjZCcXFYWEtPekgwcW51N3RnckgwQ0NGRC9hT0F5WWdYU3IvdkttMHg5RDRpZFNXTElDeTJybEt1UVpmaUNPd3pTeDgxR0N3Wm5uQT09In0="
}`
