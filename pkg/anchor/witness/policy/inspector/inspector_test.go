/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package inspector

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	anchoreventstore "github.com/trustbloc/orb/pkg/store/anchorevent"
	"github.com/trustbloc/orb/pkg/store/witness"
)

const (
	testWitnessURL = "http://localhost/services/orb"

	testMaxWitnessDelay = 600 * time.Second

	expiryTime = 10 * time.Second
)

func TestNew(t *testing.T) {
	anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
	require.NoError(t, err)

	providers := &Providers{
		AnchorEventStore: anchorEventStore,
	}

	t.Run("Success", func(t *testing.T) {
		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)
		require.NotNil(t, c)
	})
}

func TestInspector_CheckPolicy(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	anchorEvent := &vocab.AnchorEventType{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

	t.Run("success", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = anchorEventStore.Put(anchorEvent)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		provider := mem.NewProvider()

		witnessStore, err := witness.New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = witnessStore.Put(anchorEvent.Index().String(), []*proof.Witness{
			{URI: selectedWitnessURL, Selected: true},
			{URI: notSelectedWitnessURL, Selected: false},
		})
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{} },
			WitnessStore:     witnessStore,
			WitnessPolicy:    &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.NoError(t, err)
	})

	t.Run("error - get anchor event error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		provider := mem.NewProvider()

		witnessStore, err := witness.New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = witnessStore.Put(anchorEvent.Index().String(), []*proof.Witness{
			{URI: selectedWitnessURL, Selected: true},
			{URI: notSelectedWitnessURL, Selected: false},
		})
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{} },
			WitnessStore:     witnessStore,
			WitnessPolicy:    &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "get anchor event: content not found")
	})

	t.Run("error - post offer to outbox error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = anchorEventStore.Put(anchorEvent)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		provider := mem.NewProvider()

		witnessStore, err := witness.New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = witnessStore.Put(anchorEvent.Index().String(), []*proof.Witness{
			{URI: selectedWitnessURL, Selected: true},
			{URI: notSelectedWitnessURL, Selected: false},
		})
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{Err: fmt.Errorf("outbox error")} },
			WitnessStore:     witnessStore,
			WitnessPolicy:    &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbox error")
	})

	t.Run("error - no additional witnesses selected", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = anchorEventStore.Put(anchorEvent)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		provider := mem.NewProvider()

		witnessStore, err := witness.New(provider, testutil.GetExpiryService(t), expiryTime)
		require.NoError(t, err)

		err = witnessStore.Put(anchorEvent.Index().String(), []*proof.Witness{
			{URI: selectedWitnessURL, Selected: true},
			{URI: notSelectedWitnessURL, Selected: false},
		})
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{} },
			WitnessStore:     witnessStore,
			WitnessPolicy:    &mockWitnessPolicy{Witnesses: []*proof.Witness{{URI: selectedWitnessURL}}},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get additional witnesses: unable to select additional witnesses[[]] "+
			"from newly selected witnesses[[http://domain.com/service]] "+
			"and previously selected witnesses[[http://domain.com/service]]")
	})

	t.Run("error - witness store error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = anchorEventStore.Put(anchorEvent)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{} },
			WitnessStore:     &mockWitnessStore{GetErr: fmt.Errorf("witness store error")},
			WitnessPolicy:    &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - witness policy selection error", func(t *testing.T) {
		anchorEventStore, err := anchoreventstore.New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = anchorEventStore.Put(anchorEvent)
		require.NoError(t, err)

		providers := &Providers{
			AnchorEventStore: anchorEventStore,
			Outbox:           func() Outbox { return &mockOutbox{} },
			WitnessStore:     &mockWitnessStore{},
			WitnessPolicy:    &mockWitnessPolicy{Err: fmt.Errorf("witness selection error")},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorEvent.Index().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get additional witnesses: select witnesses: witness selection error")
	})
}

func TestWriter_postOfferActivity(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	testWitnessURL, err := url.Parse(testWitnessURL)
	require.NoError(t, err)

	anchorEvent := &vocab.AnchorEventType{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorEvent), anchorEvent))

	t.Run("success", func(t *testing.T) {
		providers := &Providers{
			Outbox:        func() Outbox { return &mockOutbox{} },
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, []*url.URL{testWitnessURL})
		require.NoError(t, err)
	})

	t.Run("error - post offer to outbox error", func(t *testing.T) {
		providers := &Providers{
			Outbox:        func() Outbox { return &mockOutbox{Err: fmt.Errorf("outbox error")} },
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.postOfferActivity(anchorEvent, []*url.URL{testWitnessURL})
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbox error")
	})
}

type mockOutbox struct {
	Err error
}

func (m *mockOutbox) Post(activity *vocab.ActivityType) (*url.URL, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return activity.ID().URL(), nil
}

type mockWitnessStore struct {
	GetErr    error
	UpdateErr error
}

func (w *mockWitnessStore) Get(anchorID string) ([]*proof.WitnessProof, error) {
	if w.GetErr != nil {
		return nil, w.GetErr
	}

	return nil, nil
}

func (w *mockWitnessStore) UpdateWitnessSelection(anchorID string, witnesses []*url.URL, selected bool) error {
	if w.UpdateErr != nil {
		return w.UpdateErr
	}

	return nil
}

type mockWitnessPolicy struct {
	Witnesses []*proof.Witness
	Err       error
}

func (wp *mockWitnessPolicy) Select(witnesses []*proof.Witness, _ ...*proof.Witness) ([]*proof.Witness, error) {
	if wp.Err != nil {
		return nil, wp.Err
	}

	if wp.Witnesses != nil {
		return wp.Witnesses, nil
	}

	return witnesses, nil
}

//nolint: lll
const jsonAnchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "index": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "ID": "did:orb:uAAA:EiAqm7CXVPxriNZv_A6GVCrqlmCmrUSGJ1YaheTzFxa_Fw"
            }
          ]
        },
        "subject": "hl:uEiDYMTm9nJ5B0gwpNtflwrcZCT9uT6BFiEs5sYWB45piXg:uoQ-BeEJpcGZzOi8vYmFma3JlaWd5Z2U0MzNoZTZpaGpheWtqdzI3czRmbnl6YmU3dzR0NWFpd2Vld29ucnF3YTZoZ3RjbHk"
      },
      "generator": "https://w3id.org/orb#v0",
      "tag": [
        {
          "type": "Link",
          "href": "hl:uEiDzOEQi2wRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
          "rel": [
            "witness"
          ]
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw"
    },
    {
      "contentObject": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/security/jws/v1"
        ],
        "credentialSubject": "hl:uEiDzUEQi2qRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw",
        "id": "http://orb2.domain1.com/vc/3994cc26-555c-47f1-9890-058148c154f1",
        "issuanceDate": "2021-10-14T18:32:17.894314751Z",
        "issuer": "http://orb2.domain1.com",
        "proof": [
          {
            "created": "2021-10-14T18:32:17.91Z",
            "domain": "http://orb.vct:8077/maple2020",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..h3-0HC3L87TM0j0o3Nd0VLlalcVVphwOPsfdkCLZ4q-uL4z8eO2vQ4sobbtOtFpNNZlpIOQnaWJMX3Ch5Wh-AQ",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain1.com#orb1key"
          },
          {
            "created": "2021-10-14T18:32:18.09110265Z",
            "domain": "https://orb.domain2.com",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DSL3zsltnh9dbSn3VNPb1C-6pKt6VOy-H1WadO5ZV2QZd3xZq3uRRhaShi9K1SzX-VaGPxs3gfbazJ-fpHVxBg",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:web:orb.domain2.com#orb2key"
          }
        ],
        "type": "VerifiableCredential"
      },
      "generator": "https://w3id.org/orb#v0",
      "type": "AnchorObject",
      "url": "hl:uEiDzOEQi2wRreCTfvp2AKmTaxuqUUZZNhbxe5RTBH59AWw"
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "published": "2021-10-14T18:32:17.888176489Z",
  "type": "AnchorEvent",
  "url": "hl:uEiDhdDIS_-_SWKoh5Y3KJ_sWpIoXZUPBeTBMCSBUKXpe5w:uoQ-BeEJpcGZzOi8vYmFma3JlaWhib3F6YmY3N3Ayam1rdWlwZnJ4ZmNwNnl3dXNmYm96a2R5ZjR0YXRhamVia2NzNnM2NDQ"
}`
