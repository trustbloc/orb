/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcsigner

import (
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
)

func TestSigner_New(t *testing.T) {
	providers := &Providers{
		KeyManager: &mockkms.KeyManager{},
		Crypto:     &cryptomock.Crypto{},
		Metrics:    &mocks.MetricsProvider{},
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
		DocLoader:  testutil.GetLoader(t),
		Metrics:    &mocks.MetricsProvider{},
	}

	t.Run("success - JSONWebSignature2020", func(t *testing.T) {
		s, err := New(providers, signingParams)
		require.NoError(t, err)

		signedVC, err := s.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("success - with options", func(t *testing.T) {
		s, err := New(providers, signingParams)
		require.NoError(t, err)

		now := time.Now()

		signedVC, err := s.Sign(
			&verifiable.Credential{ID: "https://example.edu/credentials/1872"},
			WithDomain("https://example.edu/credentials/2020"),
			WithCreated(now),
			WithSignatureRepresentation(verifiable.SignatureProofValue),
		)
		require.NoError(t, err)
		require.Len(t, signedVC.Proofs, 1)
		require.Equal(t, "https://example.edu/credentials/2020", signedVC.Proofs[0]["domain"])
		require.Equal(t, now.Format(time.RFC3339Nano), signedVC.Proofs[0]["created"])
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

	t.Run("success - Ed25519Signature2020", func(t *testing.T) {
		signingParamsWithED25519 := SigningParams{
			VerificationMethod: "did:abc:123#key1",
			SignatureSuite:     Ed25519Signature2020,
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
			DocLoader:  testutil.GetLoader(t),
			Metrics:    &mocks.MetricsProvider{},
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

func TestSigner_Context(t *testing.T) {
	t.Run("JSONWebSignature2020", func(t *testing.T) {
		s, err := New(&Providers{}, SigningParams{
			SignatureSuite:     JSONWebSignature2020,
			VerificationMethod: "did:abc:123#key1",
			Domain:             "domain",
		})
		require.NoError(t, err)
		require.Contains(t, s.Context(), CtxJWS)
	})

	t.Run("Ed25519Signature2018", func(t *testing.T) {
		s, err := New(&Providers{}, SigningParams{
			SignatureSuite:     Ed25519Signature2018,
			VerificationMethod: "did:abc:123#key1",
			Domain:             "domain",
		})
		require.NoError(t, err)
		require.Contains(t, s.Context(), CtxEd25519Signature2018)
	})

	t.Run("Ed25519Signature2020", func(t *testing.T) {
		s, err := New(&Providers{}, SigningParams{
			SignatureSuite:     Ed25519Signature2020,
			VerificationMethod: "did:abc:123#key1",
			Domain:             "domain",
		})
		require.NoError(t, err)
		require.Contains(t, s.Context(), CtxEd25519Signature2020)
	})

	t.Run("Not supported", func(t *testing.T) {
		s, err := New(&Providers{}, SigningParams{
			SignatureSuite:     "xxx",
			VerificationMethod: "did:abc:123#key1",
			Domain:             "domain",
		})
		require.NoError(t, err)
		require.Empty(t, s.Context())
	})
}
