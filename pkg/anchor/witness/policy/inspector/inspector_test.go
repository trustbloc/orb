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

func (m *mockOutbox) Post(activity *vocab.ActivityType, _ ...*url.URL) (*url.URL, error) {
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
  "@context": "https://w3id.org/activityanchors/v1",
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:EiCIZ19PGWe_65JLcIp_bmOu_ZrPOerFPXAoXAcdWW7iCg\",\"previousAnchor\":\"hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw\"}]},\"subject\":\"hl:uEiC0arCOQrIDw2F2Zca10gEutIrHWgIUaC1jPDRRBLADUQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQzBhckNPUXJJRHcyRjJaY2ExMGdFdXRJckhXZ0lVYUMxalBEUlJCTEFEVVE\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA\",\"id\":\"https://orb.domain2.com/vc/1636951e-9117-4134-904a-e0cd177517a1\",\"issuanceDate\":\"2022-02-10T18:50:48.682168399Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":[{\"created\":\"2022-02-10T18:50:48.682348236Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..fqgLBKohg962_3GNbH-QXklA89KBMHev95-Pk1XcGa47jq0TbFUeZi3DBGLgc-pDBisqkh0U3bUSvKY_edBAAw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},{\"created\":\"2022-02-10T18:50:48.729Z\",\"domain\":\"http://orb.vct:8077/maple2020\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..xlI19T5KT-Sy1CJuCQLIhgGHdlaK0dIjoctRwzJUz6-TpiluluGEa69aCuDjx426TgHvGXJDn8jHi5aDqGuTDA\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain1.com#orb1key2\"}],\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiB_22mkkq3lIOkoZXayxavsGnJ2HP8xR0ke_fGCKqQpyA"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiB5sZH1-ZEY0QDRbFgOrGQZqb95A95q5VWNVBBzxAJMCA",
  "parent": "hl:uEiAk0CUuIIVOxlalYH6JU7gsIwvo5zGNcM_zYo2jXwzBzw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWswQ1V1SUlWT3hsYWxZSDZKVTdnc0l3dm81ekdOY01fellvMmpYd3pCenc",
  "published": "2022-02-10T18:50:48.681998572Z",
  "type": "AnchorEvent"
}`
