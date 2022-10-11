/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package publickey

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := &mocks.Provider{}

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, nil //nolint:nilnil
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("open store error", func(t *testing.T) {
		errExpected := errors.New("injected open store error")

		p := &mocks.Provider{}
		p.OpenStoreReturns(nil, errExpected)

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, nil //nolint:nilnil
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestStore_GetPublicKey(t *testing.T) {
	t.Run("found in DB -> success", func(t *testing.T) {
		pkBytes, err := json.Marshal(&verifier.PublicKey{})
		require.NoError(t, err)

		store := &mocks.Store{}
		store.GetReturns(pkBytes, nil)

		p := &mocks.Provider{}
		p.OpenStoreReturns(store, nil)

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, nil //nolint:nilnil
		})
		require.NoError(t, err)
		require.NotNil(t, s)

		pk, err := s.GetPublicKey("did:web:orb.domain1.com", "key1")
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("fetch from remote -> success", func(t *testing.T) {
		store := &mocks.Store{}
		store.GetReturns(nil, storage.ErrDataNotFound)

		p := &mocks.Provider{}
		p.OpenStoreReturns(store, nil)

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{}, nil
		})
		require.NoError(t, err)
		require.NotNil(t, s)

		pk, err := s.GetPublicKey("did:web:orb.domain1.com", "key1")
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("fetch from remote -> error", func(t *testing.T) {
		store := &mocks.Store{}
		store.GetReturns(nil, storage.ErrDataNotFound)

		p := &mocks.Provider{}
		p.OpenStoreReturns(store, nil)

		errExpected := errors.New("injected fetch error")

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, errExpected
		})
		require.NoError(t, err)
		require.NotNil(t, s)

		pk, err := s.GetPublicKey("did:web:orb.domain1.com", "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, pk)
	})

	t.Run("DB get error -> error", func(t *testing.T) {
		errExpected := errors.New("injected get from storage error")

		store := &mocks.Store{}
		store.GetReturns(nil, errExpected)

		p := &mocks.Provider{}
		p.OpenStoreReturns(store, nil)

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return nil, nil //nolint:nilnil
		})
		require.NoError(t, err)
		require.NotNil(t, s)

		pk, err := s.GetPublicKey("did:web:orb.domain1.com", "key1")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Contains(t, err.Error(), "database error getting public key")
		require.Nil(t, pk)
	})

	t.Run("DB put error -> success", func(t *testing.T) {
		errExpected := errors.New("injected put to storage error")

		store := &mocks.Store{}
		store.GetReturns(nil, storage.ErrDataNotFound)
		store.PutReturns(errExpected)

		p := &mocks.Provider{}
		p.OpenStoreReturns(store, nil)

		s, err := New(p, func(issuerID, keyID string) (*verifier.PublicKey, error) {
			return &verifier.PublicKey{}, nil
		})
		require.NoError(t, err)
		require.NotNil(t, s)

		pk, err := s.GetPublicKey("did:web:orb.domain1.com", "key1")
		require.NoError(t, err)
		require.NotNil(t, pk)
	})
}
