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
	policymocks "github.com/trustbloc/orb/pkg/anchor/witness/policy/mocks"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	anchorlinkstore "github.com/trustbloc/orb/pkg/store/anchorlink"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

//go:generate counterfeiter -o ../mocks/witnessstore.gen.go --fake-name WitnessStore . witnessStore

const (
	testWitnessURL = "http://localhost/services/orb"

	testMaxWitnessDelay = 600 * time.Second
)

func TestNew(t *testing.T) {
	anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
	require.NoError(t, err)

	providers := &Providers{
		AnchorLinkStore: anchorLinkStore,
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

	anchorLinkset := &linkset.Linkset{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

	anchorLink := anchorLinkset.Link()
	require.NotNil(t, anchorLink)

	t.Run("success", func(t *testing.T) {
		anchorLinkBytes, err := json.Marshal(anchorLink)
		require.NoError(t, err)

		s := &mocks.Store{}
		s.GetReturns(anchorLinkBytes, nil)

		p := &mocks.Provider{}
		p.OpenStoreReturns(s, nil)

		anchorLinkStore, err := anchorlinkstore.New(p)
		require.NoError(t, err)

		err = anchorLinkStore.Put(anchorLink)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		witnessStore := &policymocks.WitnessStore{}
		witnessStore.GetReturns([]*proof.WitnessProof{
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(selectedWitnessURL), Selected: true}},
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(notSelectedWitnessURL), Selected: false}},
		}, nil)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{} },
			WitnessStore:    witnessStore,
			WitnessPolicy:   &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.NoError(t, err)
	})

	t.Run("error - get anchor event error", func(t *testing.T) {
		anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		witnessStore := &policymocks.WitnessStore{}
		witnessStore.GetReturns([]*proof.WitnessProof{
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(selectedWitnessURL), Selected: true}},
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(notSelectedWitnessURL), Selected: false}},
		}, nil)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{} },
			WitnessStore:    witnessStore,
			WitnessPolicy:   &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "get anchor event: content not found")
	})

	t.Run("error - post offer to outbox error", func(t *testing.T) {
		anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = anchorLinkStore.Put(anchorLink)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		witnessStore := &policymocks.WitnessStore{}
		witnessStore.GetReturns([]*proof.WitnessProof{
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(selectedWitnessURL), Selected: true}},
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(notSelectedWitnessURL), Selected: false}},
		}, nil)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{Err: fmt.Errorf("outbox error")} },
			WitnessStore:    witnessStore,
			WitnessPolicy:   &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "outbox error")
	})

	t.Run("error - no additional witnesses selected", func(t *testing.T) {
		anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = anchorLinkStore.Put(anchorLink)
		require.NoError(t, err)

		selectedWitnessURL, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		notSelectedWitnessURL, err := url.Parse("http://other-domain.com/service")
		require.NoError(t, err)

		witnessStore := &policymocks.WitnessStore{}
		witnessStore.GetReturns([]*proof.WitnessProof{
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(selectedWitnessURL), Selected: true}},
			{Witness: &proof.Witness{URI: vocab.NewURLProperty(notSelectedWitnessURL), Selected: false}},
		}, nil)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{} },
			WitnessStore:    witnessStore,
			WitnessPolicy:   &mockWitnessPolicy{Witnesses: []*proof.Witness{{URI: vocab.NewURLProperty(selectedWitnessURL)}}},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.Error(t, err)
		require.Contains(t, err.Error(),
			fmt.Sprintf("failed to get additional witnesses: unable to select additional witnesses for anchorID[%s] "+
				"from newly selected witnesses[[http://domain.com/service]] "+
				"and previously selected witnesses[[http://domain.com/service]]", anchorLink.Anchor()),
		)
	})

	t.Run("error - witness store error", func(t *testing.T) {
		anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = anchorLinkStore.Put(anchorLink)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{} },
			WitnessStore:    &mockWitnessStore{GetErr: fmt.Errorf("witness store error")},
			WitnessPolicy:   &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness store error")
	})

	t.Run("error - witness policy selection error", func(t *testing.T) {
		anchorLinkStore, err := anchorlinkstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = anchorLinkStore.Put(anchorLink)
		require.NoError(t, err)

		providers := &Providers{
			AnchorLinkStore: anchorLinkStore,
			Outbox:          func() Outbox { return &mockOutbox{} },
			WitnessStore:    &mockWitnessStore{},
			WitnessPolicy:   &mockWitnessPolicy{Err: fmt.Errorf("witness selection error")},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.CheckPolicy(anchorLink.Anchor().String())
		require.Error(t, err)
		require.Contains(t, err.Error(),
			fmt.Sprintf("failed to get additional witnesses: select witnesses for anchorID[%s]: witness selection error",
				anchorLink.Anchor()),
		)
	})
}

func TestWriter_postOfferActivity(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	testWitnessURL, err := url.Parse(testWitnessURL)
	require.NoError(t, err)

	anchorLinkset := &linkset.Linkset{}
	require.NoError(t, json.Unmarshal([]byte(jsonAnchorLinkset), anchorLinkset))

	anchorLink := anchorLinkset.Link()
	require.NotNil(t, anchorLink)

	t.Run("success", func(t *testing.T) {
		providers := &Providers{
			Outbox:        func() Outbox { return &mockOutbox{} },
			WitnessStore:  &mockWitnessStore{},
			WitnessPolicy: &mockWitnessPolicy{},
		}

		c, err := New(providers, testMaxWitnessDelay)
		require.NoError(t, err)

		err = c.postOfferActivity(anchorLink, []*url.URL{testWitnessURL})
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

		err = c.postOfferActivity(anchorLink, []*url.URL{testWitnessURL})
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
const jsonAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%2C%7B%22href%22%3A%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ1dLTTZxMWZHcWxwVzRIanBYWVA1S2JNOGJMUlF2X3daa0R3eVZfcnBfSlE%22%7D%2C%7B%22href%22%3A%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ18xN0I3d0dHUTYxU1ppMlFEUU1wUWNCLWNxTFp6MW1kQk9QY1QzY0FaQkE%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22id%22%3A%22https%3A%2F%2Forb.domain1.com%2Fvc%2Fd53b1df9-1acf-4389-a006-0f88496afe46%22%2C%22issuanceDate%22%3A%222022-03-15T21%3A21%3A54.62437567Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain1.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-03-15T21%3A21%3A54.631Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22gRPF8XAA4iYMwl26RmFGUoN99wuUnD_igmvIlzzDpPRLVDtmA8wrNbUdJIAKKhyMJFju8OjciSGYMY_bDRjBAw%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23orb1key2%22%7D%2C%7B%22created%22%3A%222022-03-15T21%3A21%3A54.744899145Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22FX58osRrwU11IrUfhVTi0ucrNEq05Cv94CQNvd8SdoY66fAjwU2--m8plvxwVnXmxnlV23i6htkq4qI8qrDgAA%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23orb2key%22%7D%5D%2C%22type%22%3A%22VerifiableCredential%22%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
