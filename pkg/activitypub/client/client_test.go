/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/httptransport.gen.go --fake-name HTTPTransport . httpTransport

func TestClient_GetActor(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/service1")

	actorBytes, e := json.Marshal(aptestutil.NewMockService(actorIRI))
	require.NoError(t, e)

	t.Run("Success", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write(actorBytes)
		require.NoError(t, err)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, c)

		actor, e := c.GetActor(actorIRI)
		require.NoError(t, e)
		require.NotNil(t, actor)
		require.Equal(t, actorIRI.String(), actor.ID().String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Error status code", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		rw.Code = http.StatusInternalServerError

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Nil(t, actor)
		require.Contains(t, e.Error(), "status code 500")

		require.NoError(t, result.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal client error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		actor, err := c.GetActor(actorIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Nil(t, actor)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Cache expiry", func(t *testing.T) {
		errExpected := errors.New("not found")

		t.Run("Cached", func(t *testing.T) {
			rw := httptest.NewRecorder()

			_, err := rw.Write(actorBytes)
			require.NoError(t, err)

			result := rw.Result()

			httpClient := &mocks.HTTPTransport{}
			httpClient.GetReturnsOnCall(0, result, nil)
			httpClient.GetReturnsOnCall(1, nil, errExpected)

			c := New(Config{CacheExpiration: time.Second}, httpClient,
				func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{}, nil
				}, &wellKnownResolver{})
			require.NotNil(t, t, c)

			actor, e := c.GetActor(actorIRI)
			require.NoError(t, e)
			require.NotNil(t, actor)
			require.Equal(t, actorIRI.String(), actor.ID().String())

			actor, e = c.GetActor(actorIRI)
			require.NoError(t, e)
			require.NotNil(t, actor)
			require.Equal(t, actorIRI.String(), actor.ID().String())

			require.NoError(t, result.Body.Close())
		})

		t.Run("Item expired", func(t *testing.T) {
			rw := httptest.NewRecorder()

			_, err := rw.Write(actorBytes)
			require.NoError(t, err)

			result := rw.Result()

			httpClient := &mocks.HTTPTransport{}
			httpClient.GetReturnsOnCall(0, result, nil)
			httpClient.GetReturnsOnCall(1, nil, errExpected)

			c := New(Config{CacheExpiration: time.Nanosecond}, httpClient,
				func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{}, nil
				}, &wellKnownResolver{})
			require.NotNil(t, t, c)

			actor, e := c.GetActor(actorIRI)
			require.NoError(t, e)
			require.NotNil(t, actor)
			require.Equal(t, actorIRI.String(), actor.ID().String())

			actor, e = c.GetActor(actorIRI)
			require.Error(t, e)
			require.Nil(t, actor)
			require.True(t, errors.Is(e, errExpected))

			require.NoError(t, result.Body.Close())
		})
	})

	t.Run("Resolve actor error", func(t *testing.T) {
		c := New(Config{}, &mocks.HTTPTransport{},
			func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{}, nil
			},
			&wellKnownResolver{Err: ErrNotFound})
		require.NotNil(t, c)

		actor, err := c.GetActor(actorIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), ErrNotFound.Error())
		require.Nil(t, actor)
	})

	t.Run("Resolve actor invalid URL error", func(t *testing.T) {
		c := New(Config{}, &mocks.HTTPTransport{},
			func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{}, nil
			},
			&wellKnownResolver{URI: string([]byte{0x0})})
		require.NotNil(t, c)

		actor, err := c.GetActor(actorIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid control character in URL")
		require.Nil(t, actor)
	})
}

func TestClient_GetReferences(t *testing.T) {
	log.SetLevel("activitypub_client", log.DEBUG)

	serviceIRI := testutil.MustParseURL("https://example.com/services/service1")
	collIRI := testutil.NewMockID(serviceIRI, "/followers")

	first := testutil.NewMockID(collIRI, "?page=true")
	last := testutil.NewMockID(collIRI, "?page=true&page-num=1")

	followers := []*url.URL{
		testutil.MustParseURL("https://example2.com/services/service2"),
		testutil.MustParseURL("https://example3.com/services/service3"),
		testutil.MustParseURL("https://example4.com/services/service4"),
	}

	collBytes, err := json.Marshal(aptestutil.NewMockCollection(collIRI, first, last, len(followers)))
	require.NoError(t, err)

	t.Run("Service -> Success", func(t *testing.T) {
		serviceBytes, e := json.Marshal(aptestutil.NewMockService(serviceIRI))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, e = rw.Write(serviceBytes)
		require.NoError(t, e)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(serviceIRI)
		require.NoError(t, e)
		require.NotNil(t, it)

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, 1)
		require.Equal(t, serviceIRI.String(), refs[0].String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Collection -> Success", func(t *testing.T) {
		collPage1Bytes, e := json.Marshal(aptestutil.NewMockCollectionPage(
			testutil.NewMockID(collIRI, "?page=0"),
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			collIRI, len(followers),
			vocab.NewObjectProperty(vocab.WithIRI(followers[0])),
			vocab.NewObjectProperty(vocab.WithIRI(followers[1])),
		))
		require.NoError(t, e)

		collPage2Bytes, e := json.Marshal(aptestutil.NewMockCollectionPage(
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			testutil.NewMockID(collIRI, "?page=0"),
			collIRI, len(followers),
			vocab.NewObjectProperty(vocab.WithIRI(followers[2])),
		))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, e = rw1.Write(collBytes)
		require.NoError(t, e)

		rw2 := httptest.NewRecorder()

		_, e = rw2.Write(collPage1Bytes)
		require.NoError(t, e)

		rw3 := httptest.NewRecorder()

		_, e = rw3.Write(collPage2Bytes)
		require.NoError(t, e)

		result1 := rw1.Result()
		result2 := rw2.Result()
		result3 := rw3.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)
		httpClient.GetReturnsOnCall(2, result3, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.NoError(t, e)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, len(followers))
		require.Equal(t, followers[0].String(), refs[0].String())
		require.Equal(t, followers[1].String(), refs[1].String())
		require.Equal(t, followers[2].String(), refs[2].String())

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
		require.NoError(t, result3.Body.Close())
	})

	t.Run("OrderedCollection -> Success", func(t *testing.T) {
		orderedCollBytes, e := json.Marshal(aptestutil.NewMockOrderedCollection(collIRI, first, last, len(followers)))
		require.NoError(t, e)

		collPage1Bytes, e := json.Marshal(aptestutil.NewMockOrderedCollectionPage(
			testutil.NewMockID(collIRI, "?page=0"),
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			collIRI, len(followers),
			vocab.NewObjectProperty(vocab.WithIRI(followers[0])),
			vocab.NewObjectProperty(vocab.WithIRI(followers[1])),
		))
		require.NoError(t, e)

		collPage2Bytes, e := json.Marshal(aptestutil.NewMockOrderedCollectionPage(
			testutil.NewMockID(collIRI, "?page=1"),
			nil,
			testutil.NewMockID(collIRI, "?page=0"),
			collIRI, len(followers),
			vocab.NewObjectProperty(vocab.WithIRI(followers[2])),
		))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, e = rw1.Write(orderedCollBytes)
		require.NoError(t, e)

		rw2 := httptest.NewRecorder()

		_, e = rw2.Write(collPage1Bytes)
		require.NoError(t, e)

		rw3 := httptest.NewRecorder()

		_, e = rw3.Write(collPage2Bytes)
		require.NoError(t, e)

		result1 := rw1.Result()
		result2 := rw2.Result()
		result3 := rw3.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)
		httpClient.GetReturnsOnCall(2, result3, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.NoError(t, e)
		require.NotNil(t, it)

		refs, e := ReadReferences(it, -1)
		require.NoError(t, e)
		require.Len(t, refs, len(followers))
		require.Equal(t, followers[0].String(), refs[0].String())
		require.Equal(t, followers[1].String(), refs[1].String())
		require.Equal(t, followers[2].String(), refs[2].String())

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
		require.NoError(t, result3.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal collection error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err = rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), "unexpected end of JSON input")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid collection error", func(t *testing.T) {
		invalidCollBytes, e := json.Marshal(vocab.NewObject())
		require.NoError(t, e)

		rw := httptest.NewRecorder()

		_, e = rw.Write(invalidCollBytes)
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetReferences(collIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(),
			"expecting Service, Collection, OrderedCollection, CollectionPage, or OrderedCollectionPage in response payload")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Unmarshal collection page error", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, err = rw1.Write(collBytes)
		require.NoError(t, err)

		rw2 := httptest.NewRecorder()

		_, err = rw2.Write([]byte("{"))
		require.NoError(t, err)

		result1 := rw1.Result()
		result2 := rw2.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, err := c.GetReferences(collIRI)
		require.NoError(t, err)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, err := ReadReferences(it, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Empty(t, refs)

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
	})

	t.Run("Invalid collection page error", func(t *testing.T) {
		actorIRI := testutil.MustParseURL("https://example.com/services/service1")

		invalidCollBytes, err := json.Marshal(aptestutil.NewMockService(actorIRI))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, err = rw1.Write(collBytes)
		require.NoError(t, err)

		rw2 := httptest.NewRecorder()

		_, err = rw2.Write(invalidCollBytes)
		require.NoError(t, err)

		result1 := rw1.Result()
		result2 := rw2.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, err := c.GetReferences(collIRI)
		require.NoError(t, err)
		require.NotNil(t, it)
		require.Equal(t, len(followers), it.TotalItems())

		refs, err := ReadReferences(it, -1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expecting CollectionPage or OrderedCollectionPage in response payload")
		require.Nil(t, refs)

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
	})
}

func TestClient_GetPublicKey(t *testing.T) {
	serviceIRI := testutil.MustParseURL("https://example.com/services/service1")
	keyIRI := testutil.NewMockID(serviceIRI, "/keys/main-key")

	publicKeyBytesBytes, err := json.Marshal(aptestutil.NewMockPublicKey(serviceIRI))
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err = rw.Write(publicKeyBytesBytes)
		require.NoError(t, err)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		publicKey, e := c.GetPublicKey(keyIRI)
		require.NoError(t, e)
		require.NotNil(t, publicKey)
		require.Equal(t, keyIRI.String(), publicKey.ID().String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Error status code", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		rw.Code = http.StatusInternalServerError

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		publicKey, e := c.GetPublicKey(keyIRI)
		require.Error(t, e)
		require.Nil(t, publicKey)
		require.Contains(t, e.Error(), "status code 500")

		require.NoError(t, result.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		publicKey, e := c.GetPublicKey(keyIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, publicKey)
	})

	t.Run("Unmarshal client error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err = rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		publicKey, err := c.GetPublicKey(keyIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Nil(t, publicKey)

		require.NoError(t, result.Body.Close())
	})
}

func TestClient_GetDIDPublicKey(t *testing.T) {
	serviceIRI := testutil.MustParseURL("did:web.example.com:services:service1")
	keyIRI := testutil.NewMockID(serviceIRI, "did:web.example.com:services:service1#123456")

	t.Run("Success", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubKey := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)

		c := New(Config{}, &mocks.HTTPTransport{},
			func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return &verifier.PublicKey{
					Type:  elliptic.P256().Params().Name,
					Value: pubKey,
				}, nil
			}, &wellKnownResolver{})
		require.NotNil(t, t, c)

		publicKey, err := c.GetPublicKey(keyIRI)
		require.NoError(t, err)
		require.NotNil(t, publicKey)
		require.Equal(t, keyIRI.String(), publicKey.ID().String())
	})

	t.Run("JWK", func(t *testing.T) {
		t.Run("Success", func(t *testing.T) {
			ecdsaSigner, err := signature.NewSigner(kms.ECDSASecp256k1TypeIEEEP1363)
			if err != nil {
				panic(err)
			}

			j, err := jwksupport.JWKFromKey(ecdsaSigner.PublicKey())
			if err != nil {
				panic(err)
			}

			c := New(Config{}, &mocks.HTTPTransport{},
				func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{
						Type: "JsonWebKey2020",
						JWK:  j,
					}, nil
				}, &wellKnownResolver{})
			require.NotNil(t, t, c)

			publicKey, err := c.GetPublicKey(keyIRI)
			require.NoError(t, err)
			require.NotNil(t, publicKey)
			require.Equal(t, keyIRI.String(), publicKey.ID().String())
		})

		t.Run("No key type error", func(t *testing.T) {
			c := New(Config{}, &mocks.HTTPTransport{},
				func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{
						JWK: &jwk.JWK{},
					}, nil
				}, &wellKnownResolver{})
			require.NotNil(t, t, c)

			publicKey, err := c.GetPublicKey(keyIRI)
			require.Error(t, err)
			require.Nil(t, publicKey)
			require.Contains(t, err.Error(), "no keytype recognized for jwk")
		})

		t.Run("Get public key bytes error", func(t *testing.T) {
			c := New(Config{}, &mocks.HTTPTransport{},
				func(issuerID, keyID string) (*verifier.PublicKey, error) {
					return &verifier.PublicKey{
						JWK: &jwk.JWK{
							Kty: "OKP",
							Crv: "Ed25519",
						},
					}, nil
				}, &wellKnownResolver{})
			require.NotNil(t, t, c)

			publicKey, err := c.GetPublicKey(keyIRI)
			require.Error(t, err)
			require.Nil(t, publicKey)
			require.Contains(t, err.Error(), "unsupported public key type in kid")
		})
	})

	t.Run("Fetcher error", func(t *testing.T) {
		errExpected := errors.New("injected fetcher error")

		c := New(Config{}, &mocks.HTTPTransport{},
			func(issuerID, keyID string) (*verifier.PublicKey, error) {
				return nil, errExpected
			}, &wellKnownResolver{})
		require.NotNil(t, t, c)

		publicKey, err := c.GetPublicKey(keyIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, publicKey)
	})
}

func TestClient_GetActivities(t *testing.T) {
	log.SetLevel("activitypub_client", log.DEBUG)

	service1IRI := testutil.MustParseURL("https://example.com/services/service1")
	service2IRI := testutil.MustParseURL("https://example.com/services/service2")

	collIRI := testutil.NewMockID(service1IRI, "/outbox")
	toIRI := testutil.NewMockID(service2IRI, "/inbox")
	first := testutil.NewMockID(collIRI, "?page=true")
	page0 := testutil.NewMockID(collIRI, "?page=true&page-num=0")
	page1 := testutil.NewMockID(collIRI, "?page=true&page-num=1")
	last := page1

	outboxActivities := []*vocab.ActivityType{
		newMockActivity(service1IRI, toIRI, vocab.MustParseURL("https://obj_id_1")),
		newMockActivity(service1IRI, toIRI, vocab.MustParseURL("https://obj_id_2")),
		newMockActivity(service1IRI, toIRI, vocab.MustParseURL("https://obj_id_3")),
		newMockActivity(service1IRI, toIRI, vocab.MustParseURL("https://obj_id_4")),
		newMockActivity(service1IRI, toIRI, vocab.MustParseURL("https://obj_id_5")),
	}

	collPage1Bytes, err := json.Marshal(aptestutil.NewMockCollectionPage(
		page0, page1, nil,
		collIRI, len(outboxActivities),
		vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[0])),
		vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[1])),
		vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[2])),
	))
	require.NoError(t, err)

	collPage2Bytes, err := json.Marshal(aptestutil.NewMockCollectionPage(
		page1, nil, page0,
		collIRI, len(outboxActivities),
		vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[3])),
		vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[4])),
	))
	require.NoError(t, err)

	t.Run("Collection -> Success", func(t *testing.T) {
		t.Run("Forward order", func(t *testing.T) {
			collBytes, e := json.Marshal(aptestutil.NewMockCollection(collIRI, first, last, len(outboxActivities)))
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			rw1 := httptest.NewRecorder()

			_, e = rw1.Write(collBytes)
			require.NoError(t, e)

			rw2 := httptest.NewRecorder()

			_, e = rw2.Write(collPage1Bytes)
			require.NoError(t, e)

			rw3 := httptest.NewRecorder()

			_, e = rw3.Write(collPage2Bytes)
			require.NoError(t, e)

			result1 := rw1.Result()
			result2 := rw2.Result()
			result3 := rw3.Result()

			httpClient.GetReturnsOnCall(0, result1, nil)
			httpClient.GetReturnsOnCall(1, result2, nil)
			httpClient.GetReturnsOnCall(2, result3, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, Forward)
			require.NoError(t, e)
			require.NotNil(t, it)
			require.Equal(t, len(outboxActivities), it.TotalItems())

			activities, e := ReadActivities(it, -1)
			require.NoError(t, e)
			require.Len(t, activities, len(outboxActivities))
			require.Equal(t, outboxActivities[0].ID().String(), activities[0].ID().String())
			require.Equal(t, outboxActivities[1].ID().String(), activities[1].ID().String())
			require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
			require.Equal(t, outboxActivities[3].ID().String(), activities[3].ID().String())
			require.Equal(t, outboxActivities[4].ID().String(), activities[4].ID().String())

			require.Equal(t, page1.String(), it.CurrentPage().String())

			require.NoError(t, result1.Body.Close())
			require.NoError(t, result2.Body.Close())
			require.NoError(t, result3.Body.Close())
		})

		t.Run("Reverse order", func(t *testing.T) {
			collBytes, e := json.Marshal(aptestutil.NewMockCollection(collIRI, first, last, len(outboxActivities)))
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			rw1 := httptest.NewRecorder()

			_, e = rw1.Write(collBytes)
			require.NoError(t, e)

			rw2 := httptest.NewRecorder()

			_, e = rw2.Write(collPage1Bytes)
			require.NoError(t, e)

			rw3 := httptest.NewRecorder()

			_, e = rw3.Write(collPage2Bytes)
			require.NoError(t, e)

			result1 := rw1.Result()
			result2 := rw2.Result()
			result3 := rw3.Result()

			httpClient.GetReturnsOnCall(0, result1, nil)
			httpClient.GetReturnsOnCall(1, result3, nil)
			httpClient.GetReturnsOnCall(2, result2, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, Reverse)
			require.NoError(t, e)
			require.NotNil(t, it)
			require.Equal(t, len(outboxActivities), it.TotalItems())

			activities, e := ReadActivities(it, -1)
			require.NoError(t, e)
			require.Len(t, activities, len(outboxActivities))
			require.Equal(t, outboxActivities[4].ID().String(), activities[0].ID().String())
			require.Equal(t, outboxActivities[3].ID().String(), activities[1].ID().String())
			require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
			require.Equal(t, outboxActivities[1].ID().String(), activities[3].ID().String())
			require.Equal(t, outboxActivities[0].ID().String(), activities[4].ID().String())

			require.NoError(t, result1.Body.Close())
			require.NoError(t, result2.Body.Close())
			require.NoError(t, result3.Body.Close())
		})
	})

	t.Run("OrderedCollection -> Success", func(t *testing.T) {
		t.Run("Forward order", func(t *testing.T) {
			collBytes, e := json.Marshal(aptestutil.NewMockOrderedCollection(collIRI, first, last, len(outboxActivities)))
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			rw1 := httptest.NewRecorder()

			_, e = rw1.Write(collBytes)
			require.NoError(t, e)

			rw2 := httptest.NewRecorder()

			_, e = rw2.Write(collPage1Bytes)
			require.NoError(t, e)

			rw3 := httptest.NewRecorder()

			_, e = rw3.Write(collPage2Bytes)
			require.NoError(t, e)

			result1 := rw1.Result()
			result2 := rw2.Result()
			result3 := rw3.Result()

			httpClient.GetReturnsOnCall(0, result1, nil)
			httpClient.GetReturnsOnCall(1, result2, nil)
			httpClient.GetReturnsOnCall(2, result3, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, Forward)
			require.NoError(t, e)
			require.NotNil(t, it)
			require.Equal(t, len(outboxActivities), it.TotalItems())

			activities, e := ReadActivities(it, -1)
			require.NoError(t, e)
			require.Len(t, activities, len(outboxActivities))
			require.Equal(t, outboxActivities[0].ID().String(), activities[0].ID().String())
			require.Equal(t, outboxActivities[1].ID().String(), activities[1].ID().String())
			require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
			require.Equal(t, outboxActivities[3].ID().String(), activities[3].ID().String())
			require.Equal(t, outboxActivities[4].ID().String(), activities[4].ID().String())

			require.NoError(t, result1.Body.Close())
			require.NoError(t, result2.Body.Close())
			require.NoError(t, result3.Body.Close())
		})

		t.Run("Reverse order", func(t *testing.T) {
			collBytes, e := json.Marshal(aptestutil.NewMockCollection(collIRI, first, last, len(outboxActivities)))
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			rw1 := httptest.NewRecorder()

			_, e = rw1.Write(collBytes)
			require.NoError(t, e)

			rw2 := httptest.NewRecorder()

			_, e = rw2.Write(collPage1Bytes)
			require.NoError(t, e)

			rw3 := httptest.NewRecorder()

			_, e = rw3.Write(collPage2Bytes)
			require.NoError(t, e)

			result1 := rw1.Result()
			result2 := rw2.Result()
			result3 := rw3.Result()

			httpClient.GetReturnsOnCall(0, result1, nil)
			httpClient.GetReturnsOnCall(1, result3, nil)
			httpClient.GetReturnsOnCall(2, result2, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, Reverse)
			require.NoError(t, e)
			require.NotNil(t, it)
			require.Equal(t, len(outboxActivities), it.TotalItems())

			activities, e := ReadActivities(it, -1)
			require.NoError(t, e)
			require.Len(t, activities, len(outboxActivities))
			require.Equal(t, outboxActivities[4].ID().String(), activities[0].ID().String())
			require.Equal(t, outboxActivities[3].ID().String(), activities[1].ID().String())
			require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
			require.Equal(t, outboxActivities[1].ID().String(), activities[3].ID().String())
			require.Equal(t, outboxActivities[0].ID().String(), activities[4].ID().String())

			require.NoError(t, result1.Body.Close())
			require.NoError(t, result2.Body.Close())
			require.NoError(t, result3.Body.Close())
		})

		t.Run("CollectionPage -> Success", func(t *testing.T) {
			t.Run("Forward order", func(t *testing.T) {
				httpClient := &mocks.HTTPTransport{}

				rw2 := httptest.NewRecorder()

				_, err = rw2.Write(collPage1Bytes)
				require.NoError(t, err)

				rw3 := httptest.NewRecorder()

				_, err = rw3.Write(collPage2Bytes)
				require.NoError(t, err)

				result2 := rw2.Result()
				result3 := rw3.Result()

				httpClient.GetReturnsOnCall(0, result2, nil)
				httpClient.GetReturnsOnCall(1, result3, nil)

				c := newMockClient(httpClient)
				require.NotNil(t, t, c)

				it, e := c.GetActivities(collIRI, Forward)
				require.NoError(t, e)
				require.NotNil(t, it)
				require.Equal(t, len(outboxActivities), it.TotalItems())

				activities, e := ReadActivities(it, -1)
				require.NoError(t, e)
				require.Len(t, activities, len(outboxActivities))
				require.Equal(t, outboxActivities[0].ID().String(), activities[0].ID().String())
				require.Equal(t, outboxActivities[1].ID().String(), activities[1].ID().String())
				require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
				require.Equal(t, outboxActivities[3].ID().String(), activities[3].ID().String())
				require.Equal(t, outboxActivities[4].ID().String(), activities[4].ID().String())

				require.Equal(t, page1.String(), it.CurrentPage().String())

				require.NoError(t, result2.Body.Close())
				require.NoError(t, result3.Body.Close())
			})

			t.Run("Reverse order", func(t *testing.T) {
				httpClient := &mocks.HTTPTransport{}

				rw2 := httptest.NewRecorder()

				_, err = rw2.Write(collPage1Bytes)
				require.NoError(t, err)

				rw3 := httptest.NewRecorder()

				_, err = rw3.Write(collPage2Bytes)
				require.NoError(t, err)

				result2 := rw2.Result()
				result3 := rw3.Result()

				httpClient.GetReturnsOnCall(0, result3, nil)
				httpClient.GetReturnsOnCall(1, result2, nil)

				c := newMockClient(httpClient)
				require.NotNil(t, t, c)

				it, e := c.GetActivities(collIRI, Reverse)
				require.NoError(t, e)
				require.NotNil(t, it)
				require.Equal(t, len(outboxActivities), it.TotalItems())

				activities, e := ReadActivities(it, -1)
				require.NoError(t, e)
				require.Len(t, activities, len(outboxActivities))
				require.Equal(t, outboxActivities[4].ID().String(), activities[0].ID().String())
				require.Equal(t, outboxActivities[3].ID().String(), activities[1].ID().String())
				require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
				require.Equal(t, outboxActivities[1].ID().String(), activities[3].ID().String())
				require.Equal(t, outboxActivities[0].ID().String(), activities[4].ID().String())

				require.NoError(t, result2.Body.Close())
				require.NoError(t, result3.Body.Close())
			})
		})

		t.Run("OrderedCollectionPage -> Success", func(t *testing.T) {
			t.Run("Forward order", func(t *testing.T) {
				httpClient := &mocks.HTTPTransport{}

				rw2 := httptest.NewRecorder()

				_, err = rw2.Write(collPage1Bytes)
				require.NoError(t, err)

				rw3 := httptest.NewRecorder()

				_, err = rw3.Write(collPage2Bytes)
				require.NoError(t, err)

				result2 := rw2.Result()
				result3 := rw3.Result()

				httpClient.GetReturnsOnCall(0, result2, nil)
				httpClient.GetReturnsOnCall(1, result3, nil)

				c := newMockClient(httpClient)
				require.NotNil(t, t, c)

				it, e := c.GetActivities(collIRI, Forward)
				require.NoError(t, e)
				require.NotNil(t, it)
				require.Equal(t, len(outboxActivities), it.TotalItems())

				activities, e := ReadActivities(it, -1)
				require.NoError(t, e)
				require.Len(t, activities, len(outboxActivities))
				require.Equal(t, outboxActivities[0].ID().String(), activities[0].ID().String())
				require.Equal(t, outboxActivities[1].ID().String(), activities[1].ID().String())
				require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
				require.Equal(t, outboxActivities[3].ID().String(), activities[3].ID().String())
				require.Equal(t, outboxActivities[4].ID().String(), activities[4].ID().String())

				require.Equal(t, page1.String(), it.CurrentPage().String())

				require.NoError(t, result2.Body.Close())
				require.NoError(t, result3.Body.Close())
			})

			t.Run("Reverse order", func(t *testing.T) {
				httpClient := &mocks.HTTPTransport{}

				rw2 := httptest.NewRecorder()

				_, err = rw2.Write(collPage1Bytes)
				require.NoError(t, err)

				rw3 := httptest.NewRecorder()

				_, err = rw3.Write(collPage2Bytes)
				require.NoError(t, err)

				result2 := rw2.Result()
				result3 := rw3.Result()

				httpClient.GetReturnsOnCall(0, result3, nil)
				httpClient.GetReturnsOnCall(1, result2, nil)

				c := newMockClient(httpClient)
				require.NotNil(t, t, c)

				it, e := c.GetActivities(collIRI, Reverse)
				require.NoError(t, e)
				require.NotNil(t, it)
				require.Equal(t, len(outboxActivities), it.TotalItems())

				activities, e := ReadActivities(it, -1)
				require.NoError(t, e)
				require.Len(t, activities, len(outboxActivities))
				require.Equal(t, outboxActivities[4].ID().String(), activities[0].ID().String())
				require.Equal(t, outboxActivities[3].ID().String(), activities[1].ID().String())
				require.Equal(t, outboxActivities[2].ID().String(), activities[2].ID().String())
				require.Equal(t, outboxActivities[1].ID().String(), activities[3].ID().String())
				require.Equal(t, outboxActivities[0].ID().String(), activities[4].ID().String())

				require.NoError(t, result2.Body.Close())
				require.NoError(t, result3.Body.Close())
			})
		})
	})

	t.Run("NextPage and SetNextIndex -> Success", func(t *testing.T) {
		collBytes, e := json.Marshal(aptestutil.NewMockCollection(collIRI, first, last, len(outboxActivities)))
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		rw1 := httptest.NewRecorder()

		_, e = rw1.Write(collBytes)
		require.NoError(t, e)

		rw2 := httptest.NewRecorder()

		_, e = rw2.Write(collPage1Bytes)
		require.NoError(t, e)

		rw3 := httptest.NewRecorder()

		_, e = rw3.Write(collPage2Bytes)
		require.NoError(t, e)

		result1 := rw1.Result()
		result2 := rw2.Result()
		result3 := rw3.Result()

		httpClient.GetReturnsOnCall(0, result1, nil)
		httpClient.GetReturnsOnCall(1, result2, nil)
		httpClient.GetReturnsOnCall(2, result3, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetActivities(collIRI, Forward)
		require.NoError(t, e)
		require.NotNil(t, it)
		require.Equal(t, len(outboxActivities), it.TotalItems())

		// Move to the next page (which should be the first page since we're starting with a collection).
		nextPage, err := it.NextPage()
		require.NoError(t, err)
		require.NotNil(t, nextPage)
		require.Equal(t, page0.String(), nextPage.String())
		require.Equal(t, 0, it.(*activityIterator).numProcessed)

		// Move to the next page.
		nextPage, err = it.NextPage()
		require.NoError(t, err)
		require.NotNil(t, nextPage)
		require.Equal(t, page1.String(), nextPage.String())
		require.Equal(t, 3, it.(*activityIterator).numProcessed)

		it.SetNextIndex(1)

		require.Equal(t, 1, it.NextIndex())

		activities, e := ReadActivities(it, -1)
		require.NoError(t, e)
		require.Len(t, activities, 1)
		require.Equal(t, outboxActivities[4].ID().String(), activities[0].ID().String())

		require.Equal(t, page1.String(), it.CurrentPage().String())

		require.NoError(t, result1.Body.Close())
		require.NoError(t, result2.Body.Close())
		require.NoError(t, result3.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPTransport{}

		httpClient.GetReturns(nil, errExpected)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		activities, e := c.GetActivities(collIRI, Forward)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, activities)
	})

	t.Run("Unmarshal collection error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetActivities(collIRI, Forward)
		require.Error(t, e)
		require.Contains(t, e.Error(), "unexpected end of JSON input")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid collection error", func(t *testing.T) {
		invalidCollBytes, e := json.Marshal(vocab.NewObject())
		require.NoError(t, e)

		rw := httptest.NewRecorder()

		_, e = rw.Write(invalidCollBytes)
		require.NoError(t, e)

		httpClient := &mocks.HTTPTransport{}

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		c := newMockClient(httpClient)
		require.NotNil(t, t, c)

		it, e := c.GetActivities(collIRI, Forward)
		require.Error(t, e)
		require.Contains(t, e.Error(), "invalid collection type")
		require.Nil(t, it)

		require.NoError(t, result.Body.Close())
	})

	t.Run("Invalid Order error", func(t *testing.T) {
		t.Run("Collection", func(t *testing.T) {
			collPageBytes, e := json.Marshal(aptestutil.NewMockCollection(page0, page0, page1, 5))
			require.NoError(t, e)

			rw := httptest.NewRecorder()

			_, e = rw.Write(collPageBytes)
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			result := rw.Result()

			httpClient.GetReturns(result, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, "invalid-order")
			require.Error(t, e)
			require.Contains(t, e.Error(), "invalid order [invalid-order]")
			require.Nil(t, it)

			require.NoError(t, result.Body.Close())
		})

		t.Run("CollectionPage", func(t *testing.T) {
			collPageBytes, e := json.Marshal(aptestutil.NewMockCollectionPage(
				page0, page1, nil,
				collIRI, len(outboxActivities),
				vocab.NewObjectProperty(vocab.WithActivity(outboxActivities[0])),
			))
			require.NoError(t, e)

			rw := httptest.NewRecorder()

			_, e = rw.Write(collPageBytes)
			require.NoError(t, e)

			httpClient := &mocks.HTTPTransport{}

			result := rw.Result()

			httpClient.GetReturns(result, nil)

			c := newMockClient(httpClient)
			require.NotNil(t, t, c)

			it, e := c.GetActivities(collIRI, "invalid-order")
			require.Error(t, e)
			require.Contains(t, e.Error(), "invalid order [invalid-order]")
			require.Nil(t, it)

			require.NoError(t, result.Body.Close())
		})
	})
}

func newMockActivity(service1IRI, toIRI, objID *url.URL) *vocab.ActivityType {
	return aptestutil.NewMockCreateActivity(service1IRI, toIRI,
		vocab.NewObjectProperty(
			vocab.WithObject(
				vocab.NewObject(vocab.WithID(objID)),
			),
		),
	)
}

func newMockClient(httpClient httpTransport) *Client {
	return New(Config{}, httpClient,
		func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{}, nil
		}, &wellKnownResolver{})
}

type wellKnownResolver struct {
	Err error
	URI string
}

func (m *wellKnownResolver) ResolveHostMetaLink(uri, _ string) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}

	if m.URI != "" {
		return m.URI, nil
	}

	return uri, nil
}
