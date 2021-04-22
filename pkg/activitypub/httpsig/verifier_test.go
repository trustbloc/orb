/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestVerifier_VerifyRequest(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/orb")
	pubKeyIRI := testutil.NewMockID(actorIRI, "/keys/main-key")

	signer := NewSigner(DefaultPostSignerConfig())
	require.NotNil(t, signer)

	payload := []byte("payload")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyPem, err := getPublicKeyPem(pubKey)
	require.NoError(t, err)

	publicKey := vocab.NewPublicKey(
		vocab.WithID(pubKeyIRI),
		vocab.WithOwner(actorIRI),
		vocab.WithPublicKeyPem(string(pubKeyPem)),
	)

	retriever := mocks.NewActorRetriever().
		WithPublicKey(publicKey).
		WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(publicKey)))

	t.Run("Success", func(t *testing.T) {
		v := NewVerifier(DefaultVerifierConfig(), retriever)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, publicKey.ID.String(), req, payload))

		actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.NotNil(t, actorID)
		require.Equal(t, actorIRI.String(), actorID.String())
	})

	t.Run("Invalid key ID", func(t *testing.T) {
		v := NewVerifier(DefaultVerifierConfig(), retriever)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, "invalid key \nID", req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "invalid control character in URL")
	})

	t.Run("Invalid public key pem", func(t *testing.T) {
		invalidPubKey := vocab.NewPublicKey(
			vocab.WithID(pubKeyIRI),
			vocab.WithOwner(actorIRI),
			vocab.WithPublicKeyPem("invalid"),
		)

		v := NewVerifier(
			DefaultVerifierConfig(),
			mocks.NewActorRetriever().
				WithPublicKey(invalidPubKey).
				WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(invalidPubKey))),
		)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, invalidPubKey.ID.String(), req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "invalid public key for ID")
	})

	t.Run("Public key not found -> error", func(t *testing.T) {
		v := NewVerifier(DefaultVerifierConfig(), retriever)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, "https://domainx/key1", req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
		require.Nil(t, actorID)
	})

	t.Run("Actor not found -> error", func(t *testing.T) {
		v := NewVerifier(
			DefaultVerifierConfig(),
			mocks.NewActorRetriever().WithPublicKey(publicKey),
		)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, publicKey.ID.String(), req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("Actor nil public key -> error", func(t *testing.T) {
		v := NewVerifier(
			DefaultVerifierConfig(),
			mocks.NewActorRetriever().
				WithPublicKey(publicKey).
				WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(nil))),
		)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, publicKey.ID.String(), req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "owner has nil key")
	})

	t.Run("Actor key mismatch -> error", func(t *testing.T) {
		actorPublicKey := vocab.NewPublicKey(
			vocab.WithID(testutil.NewMockID(actorIRI, "/keys/key-1")),
			vocab.WithOwner(actorIRI),
			vocab.WithPublicKeyPem(string(pubKeyPem)),
		)

		v := NewVerifier(
			DefaultVerifierConfig(),
			mocks.NewActorRetriever().
				WithPublicKey(publicKey).
				WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(actorPublicKey))),
		)
		require.NotNil(t, v)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(privKey, publicKey.ID.String(), req, payload))

		actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "public key of actor does not match the public key ID in the request")
	})
}

func getPublicKeyPem(pubKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err // nolint: wrapcheck
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   keyBytes,
	}), nil
}
