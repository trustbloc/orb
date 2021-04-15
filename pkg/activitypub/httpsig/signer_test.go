/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	t.Run("GET", func(t *testing.T) {
		s := NewSigner(DefaultGetSignerConfig())

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, "https://domain1.com", nil)
		require.NoError(t, err)

		require.NoError(t, s.SignRequest(privKey, "pubKeyID", req, nil))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("POST", func(t *testing.T) {
		s := NewSigner(DefaultPostSignerConfig())

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		payload := []byte("payload")

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, s.SignRequest(privKey, "pubKeyID", req, payload))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Digest"])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("Signer error", func(t *testing.T) {
		s := NewSigner(SignerConfig{})

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		payload := []byte("payload")

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		err = s.SignRequest(privKey, "pubKeyID", req, payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown or unsupported Digest algorithm")
	})
}
