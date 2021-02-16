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
)

func TestActor(t *testing.T) {
	const (
		serviceID  = "https://alice.example.com/services/orb"
		keyID      = "https://alice.example.com/services/orb#main-key"
		keyOwnerID = "https://alice.example.com/services/orb"
		keyPem     = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
	)

	followers := mustParseURL("https://sally.example.com/services/orb/followers")
	following := mustParseURL("https://sally.example.com/services/orb/following")
	inbox := mustParseURL("https://alice.example.com/services/orb/inbox")
	outbox := mustParseURL("https://alice.example.com/services/orb/outbox")
	witnesses := mustParseURL("https://alice.example.com/services/orb/witnesses")
	witnessing := mustParseURL("https://alice.example.com/services/orb/witnessing")
	likes := mustParseURL("https://alice.example.com/services/orb/likes")
	liked := mustParseURL("https://alice.example.com/services/orb/liked")
	shares := mustParseURL("https://alice.example.com/services/orb/shares")

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
			WithLikes(likes),
			WithLiked(liked),
			WithShares(shares),
		)

		bytes, err := canonicalizer.MarshalCanonical(service)
		require.NoError(t, err)
		t.Log(string(bytes))

		require.Equal(t, getCanonical(t, jsonService), string(bytes))
	})

	t.Run("Unmarshal", func(t *testing.T) {
		a := &ActorType{}
		require.NoError(t, json.Unmarshal([]byte(jsonService), a))
		require.NotNil(t, a.Type())
		require.True(t, a.Type().Is(TypeService))

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, serviceID, id)

		context := a.Context()
		require.NotNil(t, context)
		context.Contains(ContextActivityStreams, ContextSecurity, ContextOrb)

		key := a.GetPublicKey()
		require.NotNil(t, key)
		require.Equal(t, keyID, key.ID)
		require.Equal(t, keyOwnerID, key.Owner)
		require.Equal(t, keyPem, key.PublicKeyPem)

		in := a.GetInbox()
		require.NotNil(t, in)
		require.Equal(t, inbox.String(), in.String())

		out := a.GetOutbox()
		require.NotNil(t, out)
		require.Equal(t, outbox.String(), out.String())

		fls := a.GetFollowers()
		require.NotNil(t, fls)
		require.Equal(t, followers.String(), fls.String())

		flg := a.GetFollowing()
		require.NotNil(t, flg)
		require.Equal(t, following.String(), flg.String())

		wtns := a.GetWitnesses()
		require.NotNil(t, wtns)
		require.Equal(t, witnesses.String(), wtns.String())

		wtng := a.GetWitnessing()
		require.NotNil(t, wtng)
		require.Equal(t, witnessing.String(), wtng.String())

		lks := a.GetLikes()
		require.NotNil(t, lks)
		require.Equal(t, likes.String(), lks.String())

		lkd := a.GetLiked()
		require.NotNil(t, lkd)
		require.Equal(t, liked.String(), lkd.String())

		shrs := a.GetShares()
		require.NotNil(t, shrs)
		require.Equal(t, shares.String(), shrs.String())
	})

	t.Run("Empty actor", func(t *testing.T) {
		a := NewService(serviceID)

		id := a.ID()
		require.NotNil(t, id)
		require.Equal(t, serviceID, id)

		require.NotNil(t, a.Context())
		require.Nil(t, a.GetPublicKey())
		require.Nil(t, a.GetInbox())
		require.Nil(t, a.GetOutbox())
		require.Nil(t, a.GetFollowers())
		require.Nil(t, a.GetFollowing())
		require.Nil(t, a.GetWitnesses())
		require.Nil(t, a.GetWitnessing())
		require.Nil(t, a.GetLikes())
		require.Nil(t, a.GetLiked())
		require.Nil(t, a.GetShares())
	})
}

const jsonService = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://trustbloc.github.io/Context/orb-v1.json"
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
  "likes": "https://alice.example.com/services/orb/likes",
  "liked": "https://alice.example.com/services/orb/liked",
  "shares": "https://alice.example.com/services/orb/shares"
}
`
