/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package witness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/proof"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	anchorID = "id"
	witness  = "witness"

	expiryTime = 10 * time.Second
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - open store fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.OpenStoreReturns(nil, fmt.Errorf("open store error"))

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open anchor witness store: open store error")
		require.Nil(t, s)
	})

	t.Run("error - set store config fails", func(t *testing.T) {
		provider := &mocks.Provider{}
		provider.SetStoreConfigReturns(fmt.Errorf("set store config error"))

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to set store configuration: set store config error")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Put(anchorID, []*proof.WitnessProof{getTestWitness()})
		require.NoError(t, err)
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.BatchReturns(fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Put(anchorID, []*proof.WitnessProof{getTestWitness()})
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Put(anchorID, []*proof.WitnessProof{getTestWitness()})
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.NoError(t, err)
		require.NotEmpty(t, ops)
	})

	t.Run("success - not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - store error", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "batch error")
	})

	t.Run("error - iterator next() error", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator value() error", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(nil, fmt.Errorf("iterator value() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "iterator value() error")
	})

	t.Run("error - unmarshal anchored  witness error", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns([]byte("not-json"), nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(),
			"failed to unmarshal anchor witness from store value for anchorID[id]")
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Put(anchorID, []*proof.WitnessProof{getTestWitness()})
		require.NoError(t, err)

		ops, err := s.Get(anchorID)
		require.NoError(t, err)
		require.NotEmpty(t, ops)

		err = s.Delete(anchorID)
		require.NoError(t, err)

		ops, err = s.Get(anchorID)
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "anchorID[id] not found in the store")
	})

	t.Run("success - no witnesses found for anchor ID", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Delete(anchorID)
		require.NoError(t, err)
	})

	t.Run("error - query store error", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("query error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Delete(anchorID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "query error")
	})

	t.Run("error - iterator next() error", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Delete(anchorID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator key() error", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.KeyReturns("", fmt.Errorf("iterator key() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Delete(anchorID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator key() error")
	})

	t.Run("error - batch error", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturnsOnCall(0, true, nil)
		iterator.NextReturnsOnCall(1, false, nil)

		iterator.KeyReturnsOnCall(0, "key", nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)
		store.BatchReturns(fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.Delete(anchorID)
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}

func TestStore_AddProof(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		testWitness := &proof.WitnessProof{
			Type:    proof.WitnessTypeBatch,
			Witness: witness,
		}

		err = s.Put(anchorID, []*proof.WitnessProof{testWitness})
		require.NoError(t, err)

		wf := []byte(witnessProof)

		err = s.AddProof(anchorID, witness, wf)
		require.NoError(t, err)

		witnesses, err := s.Get(anchorID)
		require.NoError(t, err)
		require.Equal(t, len(witnesses), 1)
		bytes.Equal(wf, witnesses[0].Proof)
	})

	t.Run("success - multiple witnesses were recorded", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "witness-1",
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "witness-2",
			},
		}

		err = s.Put(anchorID, witnessProofs)
		require.NoError(t, err)

		wf := []byte(witnessProof)

		err = s.AddProof(anchorID, "witness-1", wf)
		require.NoError(t, err)

		err = s.AddProof(anchorID, "witness-2", wf)
		require.NoError(t, err)

		witnesses, err := s.Get(anchorID)
		require.NoError(t, err)
		require.Equal(t, len(witnesses), 2)
		bytes.Equal(wf, witnesses[0].Proof)
		bytes.Equal(wf, witnesses[1].Proof)
	})

	t.Run("error - witness not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "witness-1",
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "witness-2",
			},
		}

		err = s.Put(anchorID, witnessProofs)
		require.NoError(t, err)

		wf := []byte(witnessProof)

		err = s.AddProof(anchorID, "witness-3", wf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness[witness-3] not found for anchorID[id]")
	})

	t.Run("error - witness not found (no witnesses for anchor)", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - store error ", func(t *testing.T) {
		store := &mocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("batch error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})

	t.Run("error - iterator next() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator next() error")
	})

	t.Run("error - iterator value() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(nil, fmt.Errorf("iterator value() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator value() error")
	})

	t.Run("error - iterator key() error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		witnessBytes, err := json.Marshal(&proof.WitnessProof{
			Type:    proof.WitnessTypeBatch,
			Witness: witness,
		})
		require.NoError(t, err)

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(witnessBytes, nil)
		iterator.KeyReturns("", fmt.Errorf("iterator key() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "iterator key() error")
	})

	t.Run("error - store put error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		witnessBytes, err := json.Marshal(&proof.WitnessProof{
			Type:    proof.WitnessTypeBatch,
			Witness: witness,
		})
		require.NoError(t, err)

		iterator.NextReturns(true, nil)
		iterator.ValueReturns(witnessBytes, nil)
		iterator.KeyReturns("key", nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)
		store.PutReturns(fmt.Errorf("put error"))

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to add proof for anchorID[id] and witness[witness]: put error")
	})

	t.Run("error - unmarshal anchored  witness error ", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns([]byte("not-json"), nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = s.AddProof(anchorID, witness, []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to unmarshal anchor witness from store value for anchorID[id]")
	})
}

func getTestWitness() *proof.WitnessProof {
	return &proof.WitnessProof{
		Type:    proof.WitnessTypeBatch,
		Witness: "witness",
	}
}

//nolint:lll
const witnessProof = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "proof": {
    "created": "2021-04-20T20:05:35.055Z",
    "domain": "http://orb.vct:8077",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..PahivkKT6iKdnZDpkLu6uwDWYSdP7frt4l66AXI8mTsBnjgwrf9Pr-y_BkEFqsOMEuwJ3DSFdmAp1eOdTxMfDQ",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc.com#2130bhDAK-2jKsOXJiEDG909Jux4rcYEpFsYzVlqdAY"
  }
}`
