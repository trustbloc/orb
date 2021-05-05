/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	verifier2 "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
	servicemocks "github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/keyresolver.gen.go --fake-name KeyResolver . keyResolver

func TestSignatureHashAlgorithm_Create(t *testing.T) {
	const (
		kmsKeyID = "123456"
		pubKeyID = "https://example.com/services/orb/keys/main-key"
	)

	cr := &mockcrypto.Crypto{}
	km := &mockkms.KeyManager{}

	algo := NewSignerAlgorithm(cr, km, kmsKeyID)
	require.NotNil(t, algo)
	require.Equal(t, orbHTTPSigAlgorithm, algo.Algorithm())

	secret := httpsignatures.Secret{
		KeyID: pubKeyID,
	}

	data := []byte("data")

	t.Run("Success", func(t *testing.T) {
		km.GetKeyErr = nil
		cr.SignValue = []byte("signature")
		cr.SignErr = nil

		signature, err := algo.Create(secret, data)
		require.NoError(t, err)
		require.Equal(t, cr.SignValue, signature)
	})

	t.Run("Sign error", func(t *testing.T) {
		km.GetKeyErr = nil
		cr.SignValue = nil
		cr.SignErr = errors.New("injected sign error")

		signature, err := algo.Create(secret, data)
		require.Error(t, err)
		require.Contains(t, err.Error(), cr.SignErr.Error())
		require.Nil(t, signature)
	})

	t.Run("Get key error", func(t *testing.T) {
		km.GetKeyErr = errors.New("injected get key error")

		signature, err := algo.Create(secret, data)
		require.Error(t, err)
		require.Contains(t, err.Error(), km.GetKeyErr.Error())
		require.Nil(t, signature)
	})
}

func TestSignatureHashAlgorithm_Verify(t *testing.T) {
	const pubKeyID = "https://example.com/services/orb/keys/main-key"

	cr := &mockcrypto.Crypto{}
	km := &mockkms.KeyManager{}
	resolver := &mocks.KeyResolver{}

	algo := NewVerifierAlgorithm(cr, km, resolver)
	require.NotNil(t, algo)
	require.Equal(t, orbHTTPSigAlgorithm, algo.Algorithm())

	secret := httpsignatures.Secret{
		KeyID: pubKeyID,
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data := []byte("data")

	signature := ed25519.Sign(privKey, data)

	t.Run("Success", func(t *testing.T) {
		resolver.ResolveReturns(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		require.NoError(t, algo.Verify(secret, data, signature))
	})

	t.Run("Invalid signature", func(t *testing.T) {
		resolver.ResolveReturns(&verifier2.PublicKey{
			Value: pubKey,
		}, nil)

		err := algo.Verify(secret, data, []byte("invalid signature"))
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrInvalidSignature))
	})

	t.Run("ResolveKey error", func(t *testing.T) {
		errExpected := errors.New("injected resolver error")

		resolver.ResolveReturns(nil, errExpected)

		err := algo.Verify(secret, data, signature)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestKeyResolver_Resolve(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/orb")
	pubKeyIRI := testutil.NewMockID(actorIRI, "/keys/main-key")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyPem, err := getPublicKeyPem(pubKey)
	require.NoError(t, err)

	pubKeyRetriever := servicemocks.NewActorRetriever().
		WithPublicKey(vocab.NewPublicKey(
			vocab.WithID(pubKeyIRI),
			vocab.WithPublicKeyPem(string(pubKeyPem)),
		))

	t.Run("Success", func(t *testing.T) {
		resolver := NewKeyResolver(pubKeyRetriever)
		require.NotNil(t, resolver)

		pk, err := resolver.Resolve(pubKeyIRI.String())
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("Invalid key ID -> error", func(t *testing.T) {
		resolver := NewKeyResolver(pubKeyRetriever)
		require.NotNil(t, resolver)

		pk, err := resolver.Resolve(fmt.Sprintf("%s", []byte{0}))
		require.Error(t, err)
		require.Nil(t, pk)
	})

	t.Run("Key retriever error", func(t *testing.T) {
		resolver := NewKeyResolver(servicemocks.NewActorRetriever())
		require.NotNil(t, resolver)

		pk, err := resolver.Resolve(pubKeyIRI.String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "retrieve public key")
		require.Nil(t, pk)
	})

	t.Run("Invalid public key", func(t *testing.T) {
		pubKeyRetriever := servicemocks.NewActorRetriever().
			WithPublicKey(vocab.NewPublicKey(
				vocab.WithID(pubKeyIRI),
				vocab.WithPublicKeyPem("invalid key"),
			))

		resolver := NewKeyResolver(pubKeyRetriever)
		require.NotNil(t, resolver)

		pk, err := resolver.Resolve(pubKeyIRI.String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid public key")
		require.Nil(t, pk)
	})
}
