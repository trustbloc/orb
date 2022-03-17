/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package datauri

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDataURI(t *testing.T) {
	const content = `{"field1":"value1"}`

	t.Run("gzip -> success", func(t *testing.T) {
		u, err := New([]byte(content), MediaTypeDataURIGzipBase64)
		require.NoError(t, err)

		contentBytes, err := Decode(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("json -> success", func(t *testing.T) {
		u, err := New([]byte(content), MediaTypeDataURIJSON)
		require.NoError(t, err)

		contentBytes, err := Decode(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("invalid scheme -> error", func(t *testing.T) {
		u, err := url.Parse("https:application/json,some-data")
		require.NoError(t, err)

		_, err = Decode(u)
		require.EqualError(t, err, "invalid scheme for data URI")
	})

	t.Run("no content -> error", func(t *testing.T) {
		u, err := url.Parse("data:application/json")
		require.NoError(t, err)

		_, err = Decode(u)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no content in data URI")
	})

	t.Run("no media type -> error", func(t *testing.T) {
		_, err := New([]byte(content), "")
		require.EqualError(t, err, "media type not specified")

		u, err := url.Parse("data:,some-data")
		require.NoError(t, err)

		_, err = Decode(u)
		require.EqualError(t, err, "media type not specified")
	})

	t.Run("unsupported media type -> error", func(t *testing.T) {
		_, err := New([]byte(content), "unsupported")
		require.EqualError(t, err, "unsupported media type [unsupported]")

		u, err := url.Parse("data:application/unsupported,some-data")
		require.NoError(t, err)

		_, err = Decode(u)
		require.EqualError(t, err, "unsupported media type [application/unsupported]")
	})

	t.Run("json -> success", func(t *testing.T) {
		u, err := New([]byte(content), MediaTypeDataURIJSON)
		require.NoError(t, err)

		contentBytes, err := Decode(u)
		require.NoError(t, err)
		require.Equal(t, content, string(contentBytes))
	})

	t.Run("gzip decompress -> error", func(t *testing.T) {
		_, err := GzipDecompress("sfsdf")
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")
	})
}

func TestMarshalCanonical(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		data := struct {
			Field string
		}{Field: "value"}

		u, err := MarshalCanonical(data, MediaTypeDataURIJSON)
		require.NoError(t, err)
		require.NotNil(t, u)

		content, err := Decode(u)
		require.NoError(t, err)
		require.Equal(t, `{"Field":"value"}`, string(content))
	})

	t.Run("marshal error", func(t *testing.T) {
		u, err := MarshalCanonical(func() {}, MediaTypeDataURIJSON)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported type")
		require.Nil(t, u)
	})
}
