/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package unpublished

import (
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("error - from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{
			ErrOpenStore: fmt.Errorf("failed to open store"),
		}, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)})
		require.NoError(t, err)
	})

	t.Run("error - invalid operation", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte("invalid")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate key for unpublished operation for suffix[suffix]")
	})

	t.Run("error - store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrPut: fmt.Errorf("error put"),
			ErrGet: storage.ErrDataNotFound,
		}}

		s, err := New(storeProvider, time.Minute,
			testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("success - consecutive put(different operations)", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		first := &operation.AnchoredOperation{
			UniqueSuffix:     "suffix",
			OperationRequest: []byte(operationRequest),
		}

		second := &operation.AnchoredOperation{
			UniqueSuffix:     "suffix",
			OperationRequest: []byte(secondOperationRequest),
		}

		err = s.Put(first)
		require.NoError(t, err)

		err = s.Put(second)
		require.NoError(t, err)

		ops, err := s.Get("suffix")
		require.NoError(t, err)
		require.Len(t, ops, 2)
	})

	t.Run("success - consecutive put(same operation, overridden)", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)}

		err = s.Put(op)
		require.NoError(t, err)

		err = s.Put(op)
		require.NoError(t, err)

		ops, err := s.Get("suffix")
		require.NoError(t, err)
		require.Len(t, ops, 1)
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)})
		require.NoError(t, err)

		ops, err := s.Get("suffix")
		require.NoError(t, err)
		require.Equal(t, ops[0].UniqueSuffix, "suffix")
	})

	t.Run("error - operation without suffix", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.Put(&operation.AnchoredOperation{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save unpublished operation: suffix is empty")
	})

	t.Run("error - query error", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrQuery: fmt.Errorf("query error"),
		}}

		s, err := New(storeProvider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op, err := s.Get("suffix")
		require.Error(t, err)
		require.Contains(t, err.Error(), "query error")
		require.Nil(t, op)
	})

	t.Run("error - suffix not found", func(t *testing.T) {
		provider := mem.NewProvider()

		s, err := New(provider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op, err := s.Get("suffix")
		require.Error(t, err)
		require.Contains(t, err.Error(), "suffix[suffix] not found in the unpublished operation store")
		require.Nil(t, op)
	})

	t.Run("error - iterator next() error", func(t *testing.T) {
		iterator := &mocks.Iterator{}
		iterator.NextReturns(false, fmt.Errorf("iterator next() error"))

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		ops, err := s.Get("suffix")
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

		s, err := New(provider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		ops, err := s.Get("suffix")
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(), "iterator value() error")
	})

	t.Run("error - unmarshal unpublished operation error", func(t *testing.T) {
		iterator := &mocks.Iterator{}

		iterator.NextReturns(true, nil)
		iterator.ValueReturns([]byte("not-json"), nil)

		store := &mocks.Store{}
		store.QueryReturns(iterator, nil)

		provider := &mocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		s, err := New(provider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		ops, err := s.Get("suffix")
		require.Error(t, err)
		require.Nil(t, ops)
		require.Contains(t, err.Error(),
			"failed to unmarshal unpublished operation from store value for suffix[suffix]")
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)}

		err = s.Put(op)
		require.NoError(t, err)

		err = s.Delete(op)
		require.NoError(t, err)
	})

	t.Run("error - unexpected request format", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte("invalid")}

		err = s.Delete(op)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate key for unpublished operation for suffix[suffix]")
	})

	t.Run("error - from store delete", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrDelete: fmt.Errorf("delete error"),
		}}

		s, err := New(storeProvider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)}

		err = s.Delete(op)
		require.Error(t, err)
		require.Contains(t, err.Error(), "delete error")
	})
}

func TestStore_DeleteAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)}

		err = s.Put(op)
		require.NoError(t, err)

		err = s.DeleteAll([]*operation.AnchoredOperation{op})
		require.NoError(t, err)
	})

	t.Run("success - no suffixes provided", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		err = s.DeleteAll(nil)
		require.NoError(t, err)
	})

	t.Run("error - unexpected request format", func(t *testing.T) {
		s, err := New(mem.NewProvider(), time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte("invalid")}

		err = s.DeleteAll([]*operation.AnchoredOperation{op})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to generate key for unpublished operation for suffix[suffix]")
	})

	t.Run("error - from store batch", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrBatch: fmt.Errorf("batch error"),
		}}

		s, err := New(storeProvider, time.Minute, testutil.GetExpiryService(t), &orbmocks.MetricsProvider{})
		require.NoError(t, err)

		op := &operation.AnchoredOperation{UniqueSuffix: "suffix", OperationRequest: []byte(operationRequest)}

		err = s.DeleteAll([]*operation.AnchoredOperation{op})
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch error")
	})
}

const operationRequest = `
{
  "delta": {
    "patches": [
      {
        "action": "add-public-keys",
        "publicKeys": [
          {
            "id": "fourthKey",
            "publicKeyJwk": {
              "crv": "P-256K",
              "kty": "EC",
              "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
              "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
            },
            "purposes": [
              "authentication"
            ],
            "type": "JsonWebKey2020"
          }
        ]
      }
    ],
    "updateCommitment": "EiCGuEvI_J7zWChGb_uPScy34VWb0Gz3apRsaNVV_CLOBw"
  },
  "didSuffix": "EiA9MRGXT74LCs0t0rBXnv-bzbt9QXqwJamTAJeh7KYJPg",
  "revealValue": "EiD_DtWj7epHsTfUU7BiB-birenqx1YYhFGnedw7HYOKhg",
  "signedData": "eyJhbGciOiJFUzI1NiJ9.eyJhbmNob3JGcm9tIjoxNjM4ODk5MzUwLCJhbmNob3JVbnRpbCI6MTYzODg5OTY1MCwiZGVsdGFIYXNoIjoiRWlDOFpKUXFHNEdLMUtZTjZIZ2VKNkFkM014TVEzLWFIVXBuWVlSN21IS0tGdyIsInVwZGF0ZUtleSI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFCLW92RDlKdjhYV1ZqRm53Y0Q1WmlhakdRdTU5bDVxR0pZcTlveFpSYTgiLCJ5IjoiTGJqRE53amRXYXRNdTJpUW9TN2VVNHN1QTZ2NnAwZWNYTDk1aHZReEJsNCJ9fQ.6f79xW74ZOghUYRErDhGYLhpfxlnA3KIkELvew4uOwOCh5IWSeuK6k3oAnjbrxw91pcYWuo-d1s62yLvqCT38Q",
  "type": "update"
}`

const secondOperationRequest = `
{
  "delta": {
    "patches": [
      {
        "action": "add-public-keys",
        "publicKeys": [
          {
            "id": "fourthKey",
            "publicKeyJwk": {
              "crv": "P-256K",
              "kty": "EC",
              "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
              "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
            },
            "purposes": [
              "authentication"
            ],
            "type": "JsonWebKey2020"
          }
        ]
      }
    ],
    "updateCommitment": "EiAl8yc-V3SJ1Cr14IrWsz3iDFozdKAxFNPoLRu3AMlfBA"
  },
  "didSuffix": "EiAoFYojQW6itYlNqU9Ru_MwkLcpYa25ntl77p7vqkK9Tg",
  "revealValue": "EiBWIb9qHE1AaHslb8jUVu_0Wg3cSLTCIMn1MsM3zzHA_g",
  "signedData": "eyJhbGciOiJFUzI1NiJ9.eyJhbmNob3JGcm9tIjoxNjM3MjgxMzYwLCJhbmNob3JVbnRpbCI6MTYzNzI4MTY2MCwiZGVsdGFIYXNoIjoiRWlBRllucElZcEYwUnZoMzVjMEFCQUJRSTBiNzBoX1h4WHRudTd6TjF2VUo2QSIsInVwZGF0ZUtleSI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6InZadjNrYVdaalJVMFVidUctOWtNVjExZHlOOFhMZTF2NjQ3WDZDZmt5ZUUiLCJ5Ijoia0NOdFY3a0xyS1J1ZmxNTVhkQmVaZlROMEtUV2gtcmFNOVJEQk1ROV9ZNCJ9fQ.0NGxM0r8UdBmwiujxNUjQ24PaSpCPa14fYj_vfitFo4QJR8RlbErVxV-J9aXtAKpHZxqgqki749nLipS9EsVIg",
  "type": "update"
}
`
