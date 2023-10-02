/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
)

func TestEncodePublicKeyToPEM(t *testing.T) {
	t.Run("ECDSAP384IEEEP1363 -> success", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKey := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y) //nolint:staticcheck

		pem, err := EncodePublicKeyToPEM(pubKey, kms.ECDSAP256IEEEP1363)
		require.NoError(t, err)
		require.NotNil(t, pem)
	})

	t.Run("ED25519 -> success", func(t *testing.T) {
		pem, err := EncodePublicKeyToPEM(nil, kms.ED25519)
		require.NoError(t, err)
		require.NotNil(t, pem)
	})

	t.Run("ECDSAP521IEEEP1363 -> success", func(t *testing.T) {
		pem, err := EncodePublicKeyToPEM(nil, kms.ECDSAP521IEEEP1363)
		require.NoError(t, err)
		require.NotNil(t, pem)
	})

	t.Run("ECDSAP384IEEEP1363 -> success", func(t *testing.T) {
		pem, err := EncodePublicKeyToPEM(nil, kms.ECDSAP384IEEEP1363)
		require.NoError(t, err)
		require.NotNil(t, pem)
	})

	t.Run("success", func(t *testing.T) {
		pem, err := EncodePublicKeyToPEM(nil, "")
		require.NoError(t, err)
		require.NotNil(t, pem)
	})

	t.Run("ECDSAP256DER -> error", func(t *testing.T) {
		_, err := EncodePublicKeyToPEM(nil, kms.ECDSAP256DER)
		require.Error(t, err)
	})
}
