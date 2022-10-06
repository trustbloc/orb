/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
)

func TestAnchorInfoRetriever_GetAnchorInfo(t *testing.T) {
	const (
		anchorOrigin = "ipns://k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q"
		anchorURI    = "hl:uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ:uoQ-BeDVpcGZzOi8vUW1jcTZKV0RVa3l4ZWhxN1JWWmtQM052aUU0SHFSdW5SalgzOXZ1THZFSGFRTg"
		interimDID   = "interimDID:orb:uAAA:EiAWMpJJMauUlAr58MBpdWrfL9Y274xwElaCsfb0P5kmjQ"
		canonicalRef = "uEiDaapVGRRwUa8-8e0wJQknOeFDiYjnhysjsoA6vL8U60g"
	)

	t.Run("Success", func(t *testing.T) {
		resourceInfoProvider := newMockResourceInfoProvider().
			withAnchorOrigin(anchorOrigin).
			withAnchorURI(anchorURI).
			withCanonicalRef(canonicalRef)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, anchorOrigin, info.AnchorOrigin)
		require.Equal(t, anchorURI, info.AnchorURI)
		require.Equal(t, canonicalRef, info.CanonicalReference)
	})

	t.Run("Resource registry error", func(t *testing.T) {
		errExpected := errors.New("injected resource registry error")

		resourceInfoProvider := newMockResourceInfoProvider().withError(errExpected)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, info)
	})

	t.Run("No anchor origin -> error", func(t *testing.T) {
		resourceInfoProvider := newMockResourceInfoProvider().
			withAnchorOrigin(nil).
			withAnchorURI(anchorURI).
			withCanonicalRef(canonicalRef)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "property required [anchorOrigin]")
		require.Nil(t, info)
	})

	t.Run("No anchor URI -> error", func(t *testing.T) {
		resourceInfoProvider := newMockResourceInfoProvider().
			withAnchorOrigin(anchorOrigin).
			withAnchorURI("").
			withCanonicalRef(canonicalRef)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "property required [anchorURI]")
		require.Nil(t, info)
	})

	t.Run("No canonical reference -> success", func(t *testing.T) {
		resourceInfoProvider := newMockResourceInfoProvider().
			withAnchorOrigin(anchorOrigin).
			withAnchorURI(anchorURI).
			withCanonicalRef(nil)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, anchorOrigin, info.AnchorOrigin)
		require.Equal(t, anchorURI, info.AnchorURI)
		require.Equal(t, "", info.CanonicalReference)
	})

	t.Run("Invalid canonical reference -> error", func(t *testing.T) {
		resourceInfoProvider := newMockResourceInfoProvider().
			withAnchorOrigin(anchorOrigin).
			withAnchorURI(anchorURI).
			withCanonicalRef(1000)

		r := restapi.NewAnchorInfoRetriever(registry.New(registry.WithResourceInfoProvider(resourceInfoProvider)))

		info, err := r.GetAnchorInfo(interimDID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "could not assert property as a string [canonicalReference]")
		require.Nil(t, info)
	})
}
