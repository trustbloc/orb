/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/handler/mocks"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
)

//go:generate counterfeiter -o ../mocks/monitoring.gen.go --fake-name MonitoringService . monitoringSvc

func TestNew(t *testing.T) {
	var vcCh chan *verifiable.Credential

	store, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		Store: store,
	}

	c := New(providers, vcCh)
	require.NotNil(t, c)
}

func TestWitnessProofHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vcCh := make(chan *verifiable.Credential, 100)

		store, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = store.Put(anchorVC)
		require.NoError(t, err)

		providers := &Providers{
			Store:         store,
			MonitoringSvc: &mocks.MonitoringService{},
		}

		proofHandler := New(providers, vcCh)

		err = proofHandler.HandleProof("http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
			time.Now(), time.Now(), []byte(witnessProof))
		require.NoError(t, err)
	})

	t.Run("error - store error", func(t *testing.T) {
		vcCh := make(chan *verifiable.Credential, 100)

		store := &storemocks.Store{}
		store.GetReturns(nil, fmt.Errorf("get error"))

		provider := &storemocks.Provider{}
		provider.OpenStoreReturns(store, nil)

		vcStore, err := vcstore.New(provider, testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			Store:         vcStore,
			MonitoringSvc: &mocks.MonitoringService{},
		}

		proofHandler := New(providers, vcCh)

		err = proofHandler.HandleProof("http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
			time.Now(), time.Now(), []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get vc: get error")
	})

	t.Run("error - unmarshal witness proof", func(t *testing.T) {
		vcCh := make(chan *verifiable.Credential, 100)

		vcStore, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		providers := &Providers{
			Store:         vcStore,
			MonitoringSvc: &mocks.MonitoringService{},
		}

		proofHandler := New(providers, vcCh)

		err = proofHandler.HandleProof("http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
			time.Now(), time.Now(), []byte(""))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to unmarshal witness proof for anchor credential")
	})

	t.Run("error - monitoring error", func(t *testing.T) {
		vcCh := make(chan *verifiable.Credential, 100)

		store, err := vcstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		err = store.Put(anchorVC)
		require.NoError(t, err)

		monitoringSvc := &mocks.MonitoringService{}
		monitoringSvc.WatchReturns(fmt.Errorf("monitoring error"))

		providers := &Providers{
			Store:         store,
			MonitoringSvc: monitoringSvc,
		}

		proofHandler := New(providers, vcCh)

		err = proofHandler.HandleProof("http://peer1.com/vc/62c153d1-a6be-400e-a6a6-5b700b596d9d",
			time.Now(), time.Now(), []byte(witnessProof))
		require.Error(t, err)
		require.Contains(t, err.Error(), "monitoring error")
	})
}

//nolint:lll
const anchorCred = `
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

//nolint:lll
const witnessProof = `{
  "@context": [
    "https://w3id.org/security/v1",
    "https://w3id.org/jws/v1"
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
