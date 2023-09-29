/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/document"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/doctransformer/metadata"
)

func TestGetSuffix(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		suffix, err := GetSuffix("did:orb:uAAA:suffix")
		require.NoError(t, err)
		require.Equal(t, suffix, "suffix")
	})

	t.Run("error - invalid number of parts", func(t *testing.T) {
		suffix, err := GetSuffix("uAAA:suffix")
		require.Error(t, err)
		require.Empty(t, suffix)
		require.Contains(t, err.Error(), "invalid number of parts")
	})
}

func TestBetweenStrings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:uAAA:suffix", "did:orb:", ":suffix")
		require.NoError(t, err)
		require.Equal(t, str, "uAAA")
	})

	t.Run("error - doesn't contain first string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "first", "suffix")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(), "string[did:orb:cid:suffix] doesn't contain string[first]")
	})

	t.Run("error - doesn't contain second string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "cid", "second")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(), "string[did:orb:cid:suffix] doesn't contain string[second]")
	})

	t.Run("error - first string is after second string", func(t *testing.T) {
		str, err := BetweenStrings("did:orb:cid:suffix", "suffix", "did:orb")
		require.Error(t, err)
		require.Empty(t, str)
		require.Contains(t, err.Error(),
			"second string[did:orb] is before first string[suffix] in string[did:orb:cid:suffix]")
	})
}

func TestGetAnchorOrigin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = "domain.com"

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		anchorOrigin, err := GetAnchorOrigin(docMetadata)
		require.NoError(t, err)
		require.Equal(t, "domain.com", anchorOrigin)
	})

	t.Run("error - missing method metadata", func(t *testing.T) {
		docMetadata := make(document.Metadata)

		anchorOrigin, err := GetAnchorOrigin(docMetadata)
		require.Error(t, err)
		require.Empty(t, anchorOrigin)
		require.Equal(t, "missing method metadata", err.Error())
	})

	t.Run("error - missing anchor origin", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})
		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		anchorOrigin, err := GetAnchorOrigin(docMetadata)
		require.Error(t, err)
		require.Empty(t, anchorOrigin)
		require.Equal(t, "missing anchor origin property in method metadata", err.Error())
	})

	t.Run("error - wrong type for anchor origin", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})
		methodMetadata[document.AnchorOriginProperty] = 123

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		anchorOrigin, err := GetAnchorOrigin(docMetadata)
		require.Error(t, err)
		require.Empty(t, anchorOrigin)
		require.Equal(t, "anchor origin property is not a string", err.Error())
	})
}

func TestGetOperations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		unpubOps, err := GetUnpublishedOperationsFromMetadata(docMetadata)
		require.NoError(t, err)
		require.Equal(t, len(unpublishedOps), len(unpubOps))

		pubOps, err := GetPublishedOperationsFromMetadata(docMetadata)
		require.NoError(t, err)
		require.Equal(t, len(publishedOps), len(pubOps))
	})

	t.Run("error - key not found in method metadata", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		unpubOps, err := GetUnpublishedOperationsFromMetadata(docMetadata)
		require.Error(t, err)
		require.Nil(t, unpubOps)
		require.Contains(t, err.Error(), "key[unpublishedOperations] not found in method metadata")
	})

	t.Run("error - wrong metadata type", func(t *testing.T) {
		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = "invalid-type"

		unpubOps, err := GetPublishedOperationsFromMetadata(docMetadata)
		require.Error(t, err)
		require.Nil(t, unpubOps)
		require.Contains(t, err.Error(), "method metadata is wrong type[string]")
	})

	t.Run("error - missing metadata", func(t *testing.T) {
		unpublishedOps, err := GetUnpublishedOperationsFromMetadata(nil)
		require.Error(t, err)
		require.Nil(t, unpublishedOps)
		require.Contains(t, err.Error(), "missing document metadata")
	})

	t.Run("error - empty metadata", func(t *testing.T) {
		unpublishedOps, err := GetUnpublishedOperationsFromMetadata(make(document.Metadata))
		require.Error(t, err)
		require.Nil(t, unpublishedOps)
		require.Contains(t, err.Error(), "missing method metadata")
	})
}

func TestGetOperationsAfterCanonicalReference(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		anchoredOps := []*operation.AnchoredOperation{
			{Type: operation.TypeUpdate, CanonicalReference: "abc", TransactionTime: 1},
			{Type: operation.TypeUpdate, CanonicalReference: "xyz", TransactionTime: 2},
		}

		ops := GetOperationsAfterCanonicalReference("abc", anchoredOps)
		require.Equal(t, 1, len(ops))
		require.Equal(t, "xyz", ops[0].CanonicalReference)
	})
}

func TestIsDID(t *testing.T) {
	require.True(t, IsDID("did:web:example.com"))
	require.False(t, IsDID("http://example.com"))
}

func TestParseKeyURI(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		did, keyID, err := ParseKeyURI("did:web:example.com#1234")
		require.NoError(t, err)
		require.Equal(t, "did:web:example.com", did)
		require.Equal(t, "1234", keyID)
	})

	t.Run("Error", func(t *testing.T) {
		_, _, err := ParseKeyURI("did:web:example.com")
		require.EqualError(t, err, "invalid public key ID - expecting DID and key ID")
	})
}
