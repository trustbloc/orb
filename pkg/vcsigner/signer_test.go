/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcsigner

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
)

func TestSigner_New(t *testing.T) {
	providers := &Providers{
		KeyManager: &mockkms.KeyManager{},
		Crypto:     &cryptomock.Crypto{},
	}

	t.Run("success", func(t *testing.T) {
		signingParams := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			SignatureSuite:     JSONWebSignature2020,
			Domain:             "domain",
		}

		s, err := New(providers, signingParams)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - missing verification method", func(t *testing.T) {
		signingParams := SigningParams{
			SignatureSuite: JSONWebSignature2020,
			Domain:         "domain",
		}

		s, err := New(providers, signingParams)
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "failed to verify signing parameters: missing verification method")
	})
}

func TestSigner_Sign(t *testing.T) {
	signingParams := SigningParams{
		VerificationMethod: "did:abc:123#key1",
		SignatureSuite:     JSONWebSignature2020,
		Domain:             "domain",
	}

	providers := &Providers{
		KeyManager: &mockkms.KeyManager{},
		Crypto:     &cryptomock.Crypto{},
	}

	t.Run("success - JSONWebSignature2020", func(t *testing.T) {
		s, err := New(providers, signingParams)
		require.NoError(t, err)

		signedVC, err := s.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("success - Ed25519Signature2018", func(t *testing.T) {
		signingParamsWithED25519 := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			SignatureSuite:     Ed25519Signature2018,
			Domain:             "domain",
		}

		s, err := New(providers, signingParamsWithED25519)
		require.NoError(t, err)

		signedVC, err := s.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("error - invalid verification method", func(t *testing.T) {
		invalidSigningParams := SigningParams{
			VerificationMethod: "key1",
			SignatureSuite:     JSONWebSignature2020,
			Domain:             "domain",
		}

		s, err := New(providers, invalidSigningParams)
		require.NoError(t, err)

		signedVC, err := s.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid verification method format")
		require.Nil(t, signedVC)
	})

	t.Run("error - invalid signature suite", func(t *testing.T) {
		invalidSigningParams := SigningParams{
			VerificationMethod: "abc#key1",
			SignatureSuite:     "invalid",
			Domain:             "domain",
		}

		s, err := New(providers, invalidSigningParams)
		require.NoError(t, err)

		signedVC, err := s.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature type not supported: invalid")
		require.Nil(t, signedVC)
	})

	t.Run("error - error from crypto", func(t *testing.T) {
		providersWithCryptoErr := &Providers{
			KeyManager: &mockkms.KeyManager{},
			Crypto:     &cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")},
		}

		c, err := New(providersWithCryptoErr, signingParams)
		require.NoError(t, err)

		signedVC, err := c.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
		require.Nil(t, signedVC)
	})
}

func TestSigner_verifySigningParams(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		signingParams := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			SignatureSuite:     JSONWebSignature2020,
			Domain:             "domain",
		}

		err := verifySigningParams(signingParams)
		require.NoError(t, err)
	})

	t.Run("error - missing verification method", func(t *testing.T) {
		signingParams := SigningParams{
			SignatureSuite: JSONWebSignature2020,
			Domain:         "domain",
		}

		err := verifySigningParams(signingParams)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing verification method")
	})

	t.Run("error - missing signature suite", func(t *testing.T) {
		signingParams := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			Domain:             "domain",
		}

		err := verifySigningParams(signingParams)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing signature suite")
	})

	t.Run("error - missing domain", func(t *testing.T) {
		signingParams := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			SignatureSuite:     JSONWebSignature2020,
		}

		err := verifySigningParams(signingParams)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing domain")
	})
}
