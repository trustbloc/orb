/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package compression

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/compression/mocks"
)

//go:generate counterfeiter -o ./mocks/compression.gen.go --fake-name CompressionProvider . compressionProvider

func TestNew(t *testing.T) {
	t.Run("test new compression provider", func(t *testing.T) {
		p := New()
		require.NotNil(t, p)
	})
}

func TestProvider_Compress(t *testing.T) {
	testValue := []byte("test value")

	t.Run("success", func(t *testing.T) {
		p := New()

		compressionType, compressedValue, err := p.Compress(testValue)
		require.NoError(t, err)
		require.Equal(t, defaultCompressionAlgorithm, compressionType)
		require.NotEmpty(t, compressedValue)
	})

	t.Run("success - with valid compression algorithm", func(t *testing.T) {
		p := New(WithCompressionAlgorithm("GZIP"))

		compressionType, compressedValue, err := p.Compress(testValue)
		require.NoError(t, err)
		require.Equal(t, "GZIP", compressionType)
		require.NotEmpty(t, compressedValue)
	})

	t.Run("success - no compression algorithm", func(t *testing.T) {
		p := New(WithCompressionAlgorithm("None"))

		compressionType, compressedValue, err := p.Compress(testValue)
		require.NoError(t, err)
		require.Equal(t, noCompression, compressionType)
		require.Equal(t, testValue, compressedValue)
	})

	t.Run("error - invalid compression algorithm", func(t *testing.T) {
		p := New(WithCompressionAlgorithm("invalid"))

		compressionType, compressedValue, err := p.Compress([]byte("test value"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "compression algorithm 'invalid' not supported")
		require.Nil(t, compressedValue)
		require.Empty(t, compressionType)
	})

	t.Run("error - error from compression", func(t *testing.T) {
		cp := &mocks.CompressionProvider{}
		cp.CompressReturns(nil, fmt.Errorf("compression error"))

		p := New(WithCompressionProvider(cp))

		compressionType, compressedValue, err := p.Compress([]byte("test value"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "compression error")
		require.Nil(t, compressedValue)
		require.Empty(t, compressionType)
	})
}

func TestProvider_Decompress(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		p := New()

		test := []byte("test value")

		compressionType, compressedValue, err := p.Compress(test)
		require.NoError(t, err)
		require.Equal(t, defaultCompressionAlgorithm, compressionType)
		require.NotEmpty(t, compressedValue)

		decompressedValue, err := p.Decompress("id", compressedValue)
		require.NoError(t, err)
		require.Equal(t, test, decompressedValue)
	})

	t.Run("test success - with decompression algorithm", func(t *testing.T) {
		p := New(WithCompressionAlgorithm("GZIP"))

		test := []byte("test value")

		compressionType, compressedValue, err := p.Compress(test)
		require.NoError(t, err)
		require.Equal(t, defaultCompressionAlgorithm, compressionType)
		require.NotEmpty(t, compressedValue)

		decompressedValue, err := p.Decompress("id", compressedValue)
		require.NoError(t, err)
		require.Equal(t, test, decompressedValue)
	})

	t.Run("success - no compression", func(t *testing.T) {
		p := New(WithCompressionAlgorithm("None"), WithDecompressionAlgorithms([]string{"None"}))

		test := []byte("test value")

		compressionType, compressedValue, err := p.Compress(test)
		require.NoError(t, err)
		require.Equal(t, noCompression, compressionType)
		require.Equal(t, test, compressedValue)

		decompressedValue, err := p.Decompress("id", compressedValue)
		require.NoError(t, err)
		require.Equal(t, test, decompressedValue)
	})

	t.Run("error - decompression error (algorithm not supported)", func(t *testing.T) {
		p := New(WithDecompressionAlgorithms([]string{"invalid"}))

		test := []byte("test value")

		compressionType, compressedValue, err := p.Compress(test)
		require.NoError(t, err)
		require.Equal(t, defaultCompressionAlgorithm, compressionType)
		require.NotEmpty(t, compressedValue)

		decompressedValue, err := p.Decompress("id", compressedValue)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to decompress id[id] with supported algorithms[invalid]")
		require.Nil(t, decompressedValue)
	})

	t.Run("error - decompression error", func(t *testing.T) {
		p := New()

		test := []byte("test value")

		compressionType, compressedValue, err := p.Compress(test)
		require.NoError(t, err)
		require.Equal(t, defaultCompressionAlgorithm, compressionType)
		require.NotEmpty(t, compressedValue)

		cp := &mocks.CompressionProvider{}
		cp.DecompressReturns(nil, fmt.Errorf("decompression error"))

		p.coreCompressionProvider = cp

		decompressedValue, err := p.Decompress("id", compressedValue)
		require.Error(t, err)
		require.Empty(t, decompressedValue)
		require.Contains(t, err.Error(), "unable to decompress id[id] with supported algorithms[GZIP]")
	})
}
