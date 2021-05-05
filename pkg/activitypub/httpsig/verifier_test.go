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
	"fmt"
	"net/http"
	"testing"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../servicemocks/httpsigverifier.gen.go --fake-name HTTPSignatureVerifier . verifier

func TestNewVerifier(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/orb")
	pubKeyIRI := testutil.NewMockID(actorIRI, "/keys/main-key")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyPem, err := getPublicKeyPem(pubKey)
	require.NoError(t, err)

	publicKey := vocab.NewPublicKey(
		vocab.WithID(pubKeyIRI),
		vocab.WithOwner(actorIRI),
		vocab.WithPublicKeyPem(string(pubKeyPem)),
	)

	retriever := servicemocks.NewActorRetriever().
		WithPublicKey(publicKey).
		WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(publicKey)))

	v := NewVerifier(retriever, &mockcrypto.Crypto{}, &mockkms.KeyManager{})
	require.NotNil(t, v)
}

func TestVerifier_VerifyRequest(t *testing.T) {
	const keyID = "123456"

	actorIRI := testutil.MustParseURL("https://example.com/services/orb")
	pubKeyIRI := testutil.NewMockID(actorIRI, "/keys/main-key")

	signer := NewSigner(DefaultGetSignerConfig(), &mockcrypto.Crypto{}, &mockkms.KeyManager{}, keyID)
	require.NotNil(t, signer)

	payload := []byte("payload")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyPem, err := getPublicKeyPem(pubKey)
	require.NoError(t, err)

	publicKey := vocab.NewPublicKey(
		vocab.WithID(pubKeyIRI),
		vocab.WithOwner(actorIRI),
		vocab.WithPublicKeyPem(string(pubKeyPem)),
	)

	retriever := servicemocks.NewActorRetriever().
		WithPublicKey(publicKey).
		WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(publicKey)))

	t.Run("Success", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: retriever,
			verifier:       func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(publicKey.ID.String(), req))

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.True(t, ok)
		require.NotNil(t, actorID)
		require.Equal(t, actorIRI.String(), actorID.String())
	})

	t.Run("Failed verification", func(t *testing.T) {
		cr := &mockcrypto.Crypto{}
		km := &mockkms.KeyManager{}

		v := NewVerifier(retriever, cr, km)

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(publicKey.ID.String(), req))

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
	})

	t.Run("Key ID not found in signature header", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: retriever,
			verifier:       func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		req.Header["Signature"] = []string{"some header"}

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
	})

	t.Run("Invalid key ID", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: retriever,
			verifier:       func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		req.Header["Signature"] = []string{fmt.Sprintf(`keyId="%s"`, []byte{0})}

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
	})

	t.Run("Public key not found -> error", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: retriever,
			verifier:       func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest("https://domainx/key1", req))

		ok, actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.False(t, ok)
		require.Contains(t, err.Error(), "not found")
		require.Nil(t, actorID)
	})

	t.Run("Actor not found -> error", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: servicemocks.NewActorRetriever().WithPublicKey(publicKey),
			verifier:       func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(publicKey.ID.String(), req))

		ok, actorID, err := v.VerifyRequest(req)
		require.Error(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("Actor nil public key -> error", func(t *testing.T) {
		v := &Verifier{
			actorRetriever: servicemocks.NewActorRetriever().
				WithPublicKey(publicKey).
				WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(nil))),
			verifier: func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(publicKey.ID.String(), req))

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
	})

	t.Run("Actor key mismatch -> error", func(t *testing.T) {
		actorPublicKey := vocab.NewPublicKey(
			vocab.WithID(testutil.NewMockID(actorIRI, "/keys/key-1")),
			vocab.WithOwner(actorIRI),
			vocab.WithPublicKeyPem(string(pubKeyPem)),
		)

		v := &Verifier{
			actorRetriever: servicemocks.NewActorRetriever().
				WithPublicKey(publicKey).
				WithActor(aptestutil.NewMockService(actorIRI, aptestutil.WithPublicKey(actorPublicKey))),
			verifier: func() verifier { return &mocks.HTTPSignatureVerifier{} },
		}

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, signer.SignRequest(publicKey.ID.String(), req))

		ok, actorID, err := v.VerifyRequest(req)
		require.NoError(t, err)
		require.False(t, ok)
		require.Nil(t, actorID)
	})
}

func getPublicKeyPem(pubKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   keyBytes,
	}), nil
}
