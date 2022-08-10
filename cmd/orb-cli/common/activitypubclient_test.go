/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

func TestNewActivityPubClient(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := newMockCmd(func(command *cobra.Command, args []string) error { return nil })

		client, err := NewActivityPubClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}

func TestActivityPubIterator(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cmd := newMockCmd(func(command *cobra.Command, args []string) error { return nil })

		client, err := NewActivityPubClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)

		client.sendRequest = func(req []byte, method, endpointURL string) ([]byte, error) {
			if strings.Contains(endpointURL, "page-num=1") {
				return []byte(jsonCollectionLastPage), nil
			}

			if strings.Contains(endpointURL, "page=true") {
				return []byte(jsonCollectionFirstPage), nil
			}

			return []byte(jsonCollection), nil
		}

		it, err := client.GetCollection(vocab.MustParseURL("https://orb.domain1.com/services/orb/following"))
		require.NoError(t, err)
		require.NotNil(t, it)

		u, err := it.Next()
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain2.com/services/orb", u.String())

		u, err = it.Next()
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain3.com/services/orb", u.String())

		u, err = it.Next()
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain4.com/services/orb", u.String())

		_, err = it.Next()
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
	})
}

func TestActivityPubCollectionContains(t *testing.T) {
	cmd := newMockCmd(func(command *cobra.Command, args []string) error { return nil })

	t.Run("Success", func(t *testing.T) {
		collURL := vocab.MustParseURL("https://orb.domain1.com/services/orb/following")

		client, err := NewActivityPubClient(cmd)
		require.NoError(t, err)
		require.NotNil(t, client)

		client.sendRequest = func(req []byte, method, endpointURL string) ([]byte, error) {
			if strings.Contains(endpointURL, "page-num=1") {
				return []byte(jsonCollectionLastPage), nil
			}

			if strings.Contains(endpointURL, "page=true") {
				return []byte(jsonCollectionFirstPage), nil
			}

			return []byte(jsonCollection), nil
		}

		ok, err := client.CollectionContains(collURL, "https://orb.domain2.com/services/orb")
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = client.CollectionContains(collURL, "https://orb.domain4.com/services/orb")
		require.NoError(t, err)
		require.True(t, ok)

		ok, err = client.CollectionContains(collURL, "https://orb.domain5.com/services/orb")
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("HTTP error", func(t *testing.T) {
		collURL := vocab.MustParseURL("https://orb.domain1.com/services/orb/following")

		client, err := NewActivityPubClient(cmd)
		require.NoError(t, err)

		_, err = client.CollectionContains(collURL, "https://orb.domain2.com/services/orb")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
	})
}

func TestActivityPubClient_ResolveActor(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		client, err := NewActivityPubClient(newMockCmd(func(command *cobra.Command, args []string) error { return nil }))
		require.NoError(t, err)
		require.NotNil(t, client)

		client.sendRequest = func(req []byte, method, endpointURL string) ([]byte, error) {
			return []byte(jsonActor), nil
		}

		actor, err := client.ResolveActor("https://orb.domain1.com/services/anchor")
		require.NoError(t, err)
		require.NotNil(t, actor)
		require.Equal(t, "https://orb.domain1.com/services/anchor", actor.ID().String())
	})

	t.Run("Send error", func(t *testing.T) {
		client, err := NewActivityPubClient(newMockCmd(func(command *cobra.Command, args []string) error { return nil }))
		require.NoError(t, err)
		require.NotNil(t, client)

		errExpected := errors.New("injected send error")

		client.sendRequest = func(req []byte, method, endpointURL string) ([]byte, error) {
			return nil, errExpected
		}

		actor, err := client.ResolveActor("https://orb.domain1.com/services/anchor")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		client, err := NewActivityPubClient(newMockCmd(func(command *cobra.Command, args []string) error { return nil }))
		require.NoError(t, err)
		require.NotNil(t, client)

		client.sendRequest = func(req []byte, method, endpointURL string) ([]byte, error) {
			return []byte("}"), nil
		}

		actor, err := client.ResolveActor("https://orb.domain1.com/services/anchor")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unmarshal actor: invalid character")
		require.Nil(t, actor)
	})

	t.Run("Target override error", func(t *testing.T) {
		cmd := newMockCmd(func(command *cobra.Command, args []string) error { return nil })

		var args []string
		args = append(args, "--"+TargetOverrideFlagName, "orb.domain1.com")

		cmd.SetArgs(args)

		err := cmd.Execute()
		require.NoError(t, err)

		client, err := NewActivityPubClient(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid target override")
		require.Nil(t, client)
	})
}

func TestActivityPubClient_OverrideTarget(t *testing.T) {
	cmd := newMockCmd(func(command *cobra.Command, args []string) error { return nil })

	cmd.SetArgs([]string{
		"--" + TargetOverrideFlagName, "orb.domain1.com->localhost:48326",
		"--" + TargetOverrideFlagName, "orb.domain2.com->localhost:48426",
	})

	err := cmd.Execute()
	require.NoError(t, err)

	client, err := NewActivityPubClient(cmd)
	require.NoError(t, err)
	require.NotNil(t, client)

	require.Equal(t, "https://localhost:48326", client.overrideTarget("https://orb.domain1.com"))
	require.Equal(t, "https://localhost:48426", client.overrideTarget("https://orb.domain2.com"))
	require.Equal(t, "https://orb.domain3.com", client.overrideTarget("https://orb.domain3.com"))
}

const (
	jsonActor = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "https://orb.domain1.com/services/anchor",
  "publicKey": {
    "id": "https://orb.domain1.com/services/anchor/keys/main-key",
    "owner": "https://orb.domain1.com/services/anchor",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "followers": "https://orb.domain1.com/services/anchor/followers",
  "following": "https://orb.domain1.com/services/anchor/following",
  "inbox": "https://orb.domain1.com/services/anchor/inbox",
  "liked": "https://orb.domain1.com/services/anchor/liked",
  "likes": "https://orb.domain1.com/services/anchor/likes",
  "outbox": "https://orb.domain1.com/services/anchor/outbox",
  "shares": "https://orb.domain1.com/services/anchor/shares",
  "type": "Service",
  "witnesses": "https://orb.domain1.com/services/anchor/witnesses",
  "witnessing": "https://orb.domain1.com/services/anchor/witnessing"
}`

	jsonCollection = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "first": "https://orb.domain1.com/services/orb/following?page=true",
  "id": "https://orb.domain1.com/services/orb/following",
  "last": "https://orb.domain1.com/services/orb/following?page=true&page-num=1",
  "totalItems": 3,
  "type": "Collection"
 }`

	jsonCollectionFirstPage = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://orb.domain1.com/services/orb/following?page=true&page-num=0",
  "next": "https://orb.domain1.com/services/orb/following?page=true&page-num=1",
  "items": [
    "https://orb.domain2.com/services/orb",
    "https://orb.domain3.com/services/orb"
  ],
  "totalItems": 3,
  "type": "CollectionPage"
 }`

	jsonCollectionLastPage = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "https://orb.domain1.com/services/orb/following?page=true&page-num=1",
  "prev": "https://orb.domain1.com/services/orb/following?page=true&page-num=0",
  "items": [
    "https://orb.domain4.com/services/orb"
  ],
  "totalItems": 3,
  "type": "CollectionPage"
 }`
)
