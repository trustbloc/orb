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

const jsonAnchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiD1W_21fZwLNqV-T10km8jMvsT_lQZmmR4vIHQD7Wu73g",
      "author": [
        {
          "href": "https://orb.domain1.com/services/orb"
        }
      ],
      "original": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/2yOQU+DMBiG/8vndRsYFbW3zhCdOBM3lGwLWVpa4BNKR1vQSPjvhp08eH7zPO8zQI1NZaUDchiANVmpDRAoa9KFSNs4r8Tjx8PrKn7K3372uFsfV1GTtb5Wgsc3n+voVtxRde8XMAPWuTN9GKA0Mp80zp0s8Txt+EJoxbC5XGRaeVaaHjNppwHGdAbopPoLChREG046SikJcRm8B3arji3bF7S7Tl42zMbLYL5NQh7x77mMN31ldmWdPNOz72R0jrX8r+XrCsVCm2L6vuh9GNMxHX8DAAD//+QF3RoHAQAA",
          "type": "application/linkset+json"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "related": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/1TNTXOiMACA4f+SvbYrAV0rt06xfhSYCfKZHccBAhqSkIgYih3++8721vs7z/sFOG3ZreqB/fcL5G15kR2wwYXb9zV1YHIyYY0H17/GzyE0mHhpPH0LTxxhIYK53m2Rs0zuS+sMnoDqZE159S1duqr+7/S9utmz2WBR8lt255nsil/aANPxCWia/0i/l6/XsGZkE7/5u3BbowemmXfafbTl1ZCCFOGi8T6W5OVVrIyzfZfo+a1a95Jsg6F8SO2aqzGjC1aY8JIn809X+Lo4rJos9TSJYoXS9wiLngUQOyHj0WGDg4orlUSwPkT9PbPWQ2FClnEEcwZd30RzlBgLb0PmSPABt94fd1zRLMFdKWKVif5aOcHoCdKV6R6WacAqZ8+wpUZs7g1fcJE3/oO0MczbwCQWMqpUfZLG17753hRNNOYITMfpOP0LAAD//4ftAd+KAQAA",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/4xSW3OiMBT+L+mryF0uT+soVWt1amFppdPphCRIEBKFANZO//sOWtvOznRnX5Pvds753sAvxJkgBwHcJ5AKsatcWW7btt/qfV5uZE1RbRmVBBMmKMwruVFB7wuoU3yCQSRoQ8UrZCjl5U+oiqC6pOJVrmoqSCVnbSVpiqb8J5xgzTRV55Py3ANfyfw6zggSwH0D5xDABWnu1h4d7oNkiyfhaDkLpsnqGNH14mU2Z2iv8ALHgZkt5ha2h4WjbEAPUPzJHKsPL5qaRO3tch9KgapsCztbNFXwkq+iorg3mtl0NbYeakvvmLuSJzQnHf3vUXgZXzUKeL/If/zzMtb6mBeQMrWPeCE3SLbMRLdi5Eh6nJiSgW1TgpZNJGfgIIdoA0cxUBezqmrIEBlD0TlqiqZJii1pRqDqrqq6qtNXbcMe6IqlRx94Uv7D+zwAT7oNopJAQfAPuppidIpn7ofiWbDfIOHaimXJBdzlpDvURfauLne86qLCqiKloJwtiEg5vgBCmNfd91HnzNime8uIr/0s3ISNHlmPbDDN5o2I1o8BvJuwuX+78g/eZrwazierevDIjjd2ZJppen9YHPzimOIpMzx1dLNu5uvQCzg7gB4Qr7vOwjsXyacbBkVdXnI2pKQJRfBbNhdgit2WxG433bdtXaU7O1l7W3Mi3fnL4XVmoMns/lrcFOOR562sxfx3OzxytNTZ6exn5ycQnjxgnJPRZ3VBDwxPlf329Pz+JwAA//+5WD0XmwMAAA==",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
