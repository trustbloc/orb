/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDataURI(t *testing.T) {
	const content = `{"field1":"value1"}`

	t.Run("gzip -> success", func(t *testing.T) {
		u, err := NewDataURI([]byte(content), MediaTypeDataURIGzipBase64)
		require.NoError(t, err)

		contentBytes, err := DecodeDataURI(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("json -> success", func(t *testing.T) {
		u, err := NewDataURI([]byte(content), MediaTypeDataURIJSON)
		require.NoError(t, err)

		contentBytes, err := DecodeDataURI(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("invalid scheme -> error", func(t *testing.T) {
		u, err := url.Parse("https:application/json,some-data")
		require.NoError(t, err)

		_, err = DecodeDataURI(u)
		require.EqualError(t, err, "invalid scheme for data URI")
	})

	t.Run("no content -> error", func(t *testing.T) {
		u, err := url.Parse("data:application/json")
		require.NoError(t, err)

		_, err = DecodeDataURI(u)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no content in data URI")
	})

	t.Run("no media type -> error", func(t *testing.T) {
		_, err := NewDataURI([]byte(content), "")
		require.EqualError(t, err, "media type not specified")

		u, err := url.Parse("data:,some-data")
		require.NoError(t, err)

		_, err = DecodeDataURI(u)
		require.EqualError(t, err, "media type not specified")
	})

	t.Run("unsupported media type -> error", func(t *testing.T) {
		_, err := NewDataURI([]byte(content), "unsupported")
		require.EqualError(t, err, "unsupported media type [unsupported]")

		u, err := url.Parse("data:application/unsupported,some-data")
		require.NoError(t, err)

		_, err = DecodeDataURI(u)
		require.EqualError(t, err, "unsupported media type [application/unsupported]")
	})

	t.Run("json -> success", func(t *testing.T) {
		u, err := NewDataURI([]byte(content), MediaTypeDataURIJSON)
		require.NoError(t, err)

		contentBytes, err := DecodeDataURI(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("gzip decompress -> error", func(t *testing.T) {
		_, err := GzipDecompress("sfsdf")
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
	})
}
