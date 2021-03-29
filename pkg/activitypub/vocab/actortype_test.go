/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestActor(t *testing.T) {
	const (
		keyID      = "https://alice.example.com/services/orb#main-key"
		keyOwnerID = "https://alice.example.com/services/orb"
		keyPem     = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
	)

	serviceID := testutil.MustParseURL("https://alice.example.com/services/orb")
	followers := testutil.MustParseURL("https://sally.example.com/services/orb/followers")
	following := testutil.MustParseURL("https://sally.example.com/services/orb/following")
	inbox := testutil.MustParseURL("https://alice.example.com/services/orb/inbox")
	outbox := testutil.MustParseURL("https://alice.example.com/services/orb/outbox")
	witnesses := testutil.MustParseURL("https://alice.example.com/services/orb/witnesses")
	witnessing := testutil.MustParseURL("https://alice.example.com/services/orb/witnessing")
	liked := testutil.MustParseURL("https://alice.example.com/services/orb/liked")

	publicKey := &PublicKeyType{
		ID:           keyID,
		Owner:        keyOwnerID,
		PublicKeyPem: keyPem,
	}

	t.Run("Marshal", func(t *testing.T) {
		service := NewService(serviceID,
			WithPublicKey(publicKey),
			WithInbox(inbox),
			WithOutbox(outbox),
			WithFollowers(followers),
			WithFollowing(following),
			WithWitnesses(witnesses),
			WithWitnessing(witnessing),
			WithLiked(liked),
		)

		bytes, err := canonicalizer.MarshalCanonical(service)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, testutil.GetCanonical(t, jsonService), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActorType{}
		require.NoError(t, json.Unmarshal([]byte(jsonService), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeService))

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, serviceID.String(), id.String())

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams, ContextSecurity, ContextOrb)

		key := a.PublicKey()
		require.NotNil(t, key)
		require.Equal(t, keyID, key.ID)
		require.Equal(t, keyOwnerID, key.Owner)
		require.Equal(t, keyPem, key.PublicKeyPem)

		in := a.Inbox()
		require.NotNil(t, in)
		require.Equal(t, inbox.String(), in.String())

		out := a.Outbox()
		require.NotNil(t, out)
		require.Equal(t, outbox.String(), out.String())

		fls := a.Followers()
		require.NotNil(t, fls)
		require.Equal(t, followers.String(), fls.String())

		flg := a.Following()
		require.NotNil(t, flg)
		require.Equal(t, following.String(), flg.String())

		wtns := a.Witnesses()
		require.NotNil(t, wtns)
		require.Equal(t, witnesses.String(), wtns.String())

		wtng := a.Witnessing()
		require.NotNil(t, wtng)
		require.Equal(t, witnessing.String(), wtng.String())

		lkd := a.Liked()
		require.NotNil(t, lkd)
		require.Equal(t, liked.String(), lkd.String())
	})

	t.Run("Empty actor", func(t *testing.T) {
		a := NewService(serviceID)

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, serviceID.String(), id.String())

		require.NotNil(t, a.Context())
		require.Nil(t, a.PublicKey())
		require.Nil(t, a.Inbox())
		require.Nil(t, a.Outbox())
		require.Nil(t, a.Followers())
		require.Nil(t, a.Following())
		require.Nil(t, a.Witnesses())
		require.Nil(t, a.Witnessing())
		require.Nil(t, a.Liked())
	})
}

const jsonService = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
  ],
  "id": "https://alice.example.com/services/orb",
  "type": "Service",
  "publicKey": {
    "id": "https://alice.example.com/services/orb#main-key",
    "owner": "https://alice.example.com/services/orb",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "inbox": "https://alice.example.com/services/orb/inbox",
  "outbox": "https://alice.example.com/services/orb/outbox",
  "followers": "https://sally.example.com/services/orb/followers",
  "following": "https://sally.example.com/services/orb/following",
  "witnesses": "https://alice.example.com/services/orb/witnesses",
  "witnessing": "https://alice.example.com/services/orb/witnessing",
  "liked": "https://alice.example.com/services/orb/liked"
}
`
