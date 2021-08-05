/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package multihash_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/multihash"
)

func TestIsValidCID(t *testing.T) {
	t.Run("success - false", func(t *testing.T) {
		valid := multihash.IsValidCID("uEiAWradITyYpRGT3pMhcKfPL8kpJBGePjFjZOlS0zqAUqw")
		require.False(t, valid)
	})
	t.Run("success - true", func(t *testing.T) {
		valid := multihash.IsValidCID("bafkreibx3pob32ai67uyizvhwndjdydzaa45ln6acf2mmtb7g7l3epateq")
		require.True(t, valid)
	})

	t.Run("success - false", func(t *testing.T) {
		valid := multihash.IsValidCID("hello")
		require.False(t, valid)
	})

	t.Run("success - ipns", func(t *testing.T) {
		valid := multihash.IsValidCID("/ipns/k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q/.well-known/host-meta.json") //nolint:lll
		require.True(t, valid)
	})
}

func TestToV0CID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		v1CID, err := multihash.ToV0CID("uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA")
		require.NoError(t, err)
		require.Equal(t, "QmS6haUrtQ8tcTTLCMdknWXAhUci1g1wfHorxM65RxNc5R", v1CID)
	})
	t.Run("Fail to decode multibase-encoded multihash", func(t *testing.T) {
		v1CID, err := multihash.ToV0CID("")
		require.EqualError(t, err, "failed to decode multibase-encoded multihash: "+
			"cannot decode multibase for zero length string")
		require.Empty(t, v1CID)
	})
	t.Run("Fail to parse the decoded multibase value as a multihash", func(t *testing.T) {
		v1CID, err := multihash.ToV0CID("u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF")
		require.EqualError(t, err, "failed to parse the decoded multibase value as a multihash: "+
			"length greater than remaining number of bytes in buffer")
		require.Empty(t, v1CID)
	})
}

func TestToV1CID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		v1CID, err := multihash.ToV1CID("uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA")
		require.NoError(t, err)
		require.Equal(t, "bafkreibx3pob32ai67uyizvhwndjdydzaa45ln6acf2mmtb7g7l3epateq", v1CID)
	})
	t.Run("Fail to decode multibase-encoded multihash", func(t *testing.T) {
		v1CID, err := multihash.ToV1CID("")
		require.EqualError(t, err, "failed to decode multibase-encoded multihash: "+
			"cannot decode multibase for zero length string")
		require.Empty(t, v1CID)
	})
	t.Run("Fail to parse the decoded multibase value as a multihash", func(t *testing.T) {
		v1CID, err := multihash.ToV1CID("u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF")
		require.EqualError(t, err, "failed to parse the decoded multibase value as a multihash: "+
			"length greater than remaining number of bytes in buffer")
		require.Empty(t, v1CID)
	})
}

func TestCIDToMultihash(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		t.Run("V0 CID", func(t *testing.T) {
			multihashFromCID, err := multihash.CIDToMultihash("QmXtH52gwKmNzfe6PmPf9jmiZ7zuhGmx577bHonXpvKSgL")
			require.NoError(t, err)
			require.Equal(t, "uEiCN00z3Gj3oGUbIREZud0Puv-OE4N2x9eTJ0vFMTaju7Q", multihashFromCID)
		})
		t.Run("V1 CID", func(t *testing.T) {
			multihashFromCID, err := multihash.CIDToMultihash("bafkreibx3pob32ai67uyizvhwndjdydzaa45ln6acf2mmtb7g7l3epateq")
			require.NoError(t, err)
			require.Equal(t, "uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA", multihashFromCID)
		})
	})
	t.Run("Fail to decode CID", func(t *testing.T) {
		multihashFromCID, err := multihash.CIDToMultihash("")
		require.EqualError(t, err, "failed to decode CID: cid too short")
		require.Empty(t, multihashFromCID)
	})
}
