/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestURLProperty(t *testing.T) {
	const (
		address = "https://example.com"
		jsonURL = `"https://example.com"`
	)

	u, err := url.Parse(address)
	require.NoError(t, err)

	require.Nil(t, NewURLProperty(nil))

	p := NewURLProperty(u)
	require.NotNil(t, p)
	require.Equal(t, u, p.URL())
	require.Equal(t, u.String(), p.String())

	bytes, err := json.Marshal(p)
	require.NoError(t, err)
	require.Equal(t, jsonURL, string(bytes))

	p2 := &URLProperty{}
	require.NoError(t, json.Unmarshal(bytes, p2))
	require.Equal(t, u.String(), p2.String())
}

func TestURLCollectionProperty(t *testing.T) {
	const (
		address1          = "https://example1.com"
		address2          = "https://example2.com"
		jsonURL           = `"https://example1.com"`
		jsonURLCollection = `["https://example1.com","https://example2.com"]`
	)

	u1, err := url.Parse(address1)
	require.NoError(t, err)

	u2, err := url.Parse(address2)
	require.NoError(t, err)

	require.Nil(t, NewURLCollectionProperty())

	t.Run("Single URL", func(t *testing.T) {
		p := NewURLCollectionProperty(u1)
		require.NotNil(t, p)

		urls := p.URLs()
		require.Len(t, urls, 1)
		require.Equal(t, u1, urls[0])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)

		p2 := &URLCollectionProperty{}
		require.NoError(t, json.Unmarshal(bytes, p2))
		require.Equal(t, jsonURL, string(bytes))

		urls = p2.URLs()
		require.Len(t, urls, 1)
		require.Equal(t, u1, urls[0])
	})

	t.Run("Multiple URLs", func(t *testing.T) {
		p := NewURLCollectionProperty(u1, u2)
		require.NotNil(t, p)

		urls := p.URLs()
		require.Len(t, urls, 2)
		require.Equal(t, u1, urls[0])
		require.Equal(t, u2, urls[1])

		bytes, err := json.Marshal(p)
		require.NoError(t, err)

		p2 := &URLCollectionProperty{}
		require.NoError(t, json.Unmarshal(bytes, p2))
		require.Equal(t, jsonURLCollection, string(bytes))

		urls = p2.URLs()
		require.Len(t, urls, 2)
		require.Equal(t, u1, urls[0])
		require.Equal(t, u2, urls[1])
	})
}
