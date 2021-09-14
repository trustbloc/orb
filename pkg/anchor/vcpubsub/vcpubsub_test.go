/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcpubsub

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

func TestNewSubscriber(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s, err := NewSubscriber(&mocks.PubSub{}, nil, testutil.GetLoader(t))
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeReturns(nil, errExpected)

		s, err := NewSubscriber(ps, nil, testutil.GetLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestPubSub(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	p := NewPublisher(ps)
	require.NotNil(t, p)

	var mutex sync.RWMutex

	var gotVCs []*verifiable.Credential

	s, err := NewSubscriber(ps,
		func(vc *verifiable.Credential) error {
			mutex.Lock()
			gotVCs = append(gotVCs, vc)
			mutex.Unlock()

			return nil
		},
		testutil.GetLoader(t),
	)
	require.NoError(t, err)
	require.NotNil(t, s)

	s.Start()

	vc, err := verifiable.ParseCredential([]byte(anchorCred),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
	)
	require.NoError(t, err)

	require.NoError(t, p.Publish(vc))

	time.Sleep(100 * time.Millisecond)

	mutex.RLock()
	require.Len(t, gotVCs, 1)
	require.Equal(t, vc.ID, gotVCs[0].ID)
	mutex.RUnlock()
}

func TestPublisherError(t *testing.T) {
	vc, err := verifiable.ParseCredential([]byte(anchorCred),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
	)
	require.NoError(t, err)

	t.Run("Marshal error", func(t *testing.T) {
		p := NewPublisher(&mocks.PubSub{})
		require.NotNil(t, p)

		errExpected := errors.New("injected marshal error")

		p.jsonMarshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = p.Publish(vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Publish error", func(t *testing.T) {
		errExpected := errors.New("injected publish error")

		ps := &mocks.PubSub{}
		ps.PublishReturns(errExpected)

		p := NewPublisher(ps)
		require.NotNil(t, p)

		err = p.Publish(vc)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})
}

func TestSubscriberError(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	p := NewPublisher(ps)
	require.NotNil(t, p)

	t.Run("Invalid verifiable credential", func(t *testing.T) {
		var mutex sync.RWMutex

		var gotVCs []*verifiable.Credential

		s, err := NewSubscriber(ps,
			func(vc *verifiable.Credential) error {
				mutex.Lock()
				gotVCs = append(gotVCs, vc)
				mutex.Unlock()

				return nil
			},
			testutil.GetLoader(t),
		)
		require.NoError(t, err)
		require.NotNil(t, s)

		s.Start()

		require.NoError(t, p.Publish(&verifiable.Credential{}))

		time.Sleep(100 * time.Millisecond)

		mutex.RLock()
		require.Empty(t, gotVCs)
		mutex.RUnlock()
	})

	t.Run("Process error", func(t *testing.T) {
		vc, err := verifiable.ParseCredential([]byte(anchorCred),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)),
		)
		require.NoError(t, err)

		t.Run("Transient error", func(t *testing.T) {
			var mutex sync.RWMutex

			var gotVCs []*verifiable.Credential

			s, err := NewSubscriber(ps,
				func(vc *verifiable.Credential) error {
					mutex.Lock()
					gotVCs = append(gotVCs, vc)
					mutex.Unlock()

					return orberrors.NewTransient(errors.New("injected transient error"))
				},
				testutil.GetLoader(t),
			)
			require.NoError(t, err)
			require.NotNil(t, s)

			s.Start()

			require.NoError(t, p.Publish(vc))

			time.Sleep(100 * time.Millisecond)

			mutex.RLock()
			require.Len(t, gotVCs, 1)
			mutex.RUnlock()
		})

		t.Run("Persistent error", func(t *testing.T) {
			var mutex sync.RWMutex

			var gotVCs []*verifiable.Credential

			s, err := NewSubscriber(ps,
				func(vc *verifiable.Credential) error {
					mutex.Lock()
					gotVCs = append(gotVCs, vc)
					mutex.Unlock()

					return errors.New("injected persistent error")
				},
				testutil.GetLoader(t),
			)
			require.NoError(t, err)
			require.NotNil(t, s)

			s.Start()

			require.NoError(t, p.Publish(vc))

			time.Sleep(100 * time.Millisecond)

			mutex.RLock()
			require.Len(t, gotVCs, 1)
			mutex.RUnlock()
		})
	})
}

//nolint: lll
var anchorCred = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "credentialSubject": {},
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
