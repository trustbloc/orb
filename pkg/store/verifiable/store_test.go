/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals,lll
var udCredential = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z"
}
`

//nolint:gochecknoglobals,lll
var udCredentialWithoutID = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z"
}
`

//nolint:gochecknoglobals,lll
var anchorCred = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "credentialSubject": {
    "coreIndex": "QmZzPwGc3JEMQDiJu21YZcdpEPam7qCoXPLEUQXn34sMhB",
    "namespace": "did:sidetree",
    "operationCount": 1,
    "previousAnchors": {
      "EiBjG9z921eyj8wI4j-LAqsJBRC_GalIUWPJeXGekxFQ-w": ""
    },
    "version": 0
  },
  "id": "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
  "issuanceDate": "2021-03-17T20:01:10.4002903Z",
  "issuer": "http://peer1.com",
  "proof": {
    "created": "2021-03-17T20:01:10.4024292Z",
    "domain": "domain.com",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..pHA1rMSsHBJLbDwRpNY0FrgSgoLzBw4S7VP7d5bkYW-JwU8qc_4CmPfQctR8kycQHSa2Jh8LNBqNKMeVWsAwDA",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc#CvSyX0VxMCbg-UiYpAVd9OmhaFBXBr5ISpv2RZ2c9DY"
  },
  "type": "VerifiableCredential"
}`

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockstore.MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
		},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("test save vc - success", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		err = s.Put(&verifiable.Credential{ID: "vc1"})
		require.NoError(t, err)
	})

	t.Run("test save vc - error from store put", func(t *testing.T) {
		storeProvider := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrPut: fmt.Errorf("error put"),
		})

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Put(&verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		udVC, err := verifiable.ParseCredential([]byte(udCredential))
		require.NoError(t, err)

		err = s.Put(udVC)
		require.NoError(t, err)

		vc, err := s.Get("http://example.edu/credentials/1872")
		require.NoError(t, err)
		require.Equal(t, vc.ID, "http://example.edu/credentials/1872")
	})

	t.Run("test success - with proof", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = s.Put(anchorVC)
		require.NoError(t, err)

		vc, err := s.Get(anchorVC.ID)
		require.NoError(t, err)
		require.Equal(t, vc.ID, "http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d")
	})

	t.Run("error - vc without ID", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		udVC, err := verifiable.ParseCredential([]byte(udCredentialWithoutID))
		require.NoError(t, err)

		err = s.Put(udVC)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save vc: ID is empty")
	})

	t.Run("test error from store get", func(t *testing.T) {
		storeProvider := mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
			Store:  make(map[string]mockstore.DBEntry),
			ErrGet: fmt.Errorf("error get"),
		})

		s, err := New(storeProvider)
		require.NoError(t, err)

		vc, err := s.Get("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("test error from new credential", func(t *testing.T) {
		s, err := New(mockstore.NewMockStoreProvider())
		require.NoError(t, err)

		err = s.Put(&verifiable.Credential{ID: "vc1"})
		require.NoError(t, err)

		vc, err := s.Get("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, vc)
	})
}
