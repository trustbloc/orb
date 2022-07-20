/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorlinkset

import (
	"encoding/json"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
)

const (
	namespace = "did:orb"

	anchorOrigin = "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p"
	coreIndex    = "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95" //nolint:lll

	updateSuffix     = "uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA"
	updatePrevAnchor = "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5" //nolint:lll

	createSuffix = "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
)

func TestBuildAnchorLink(t *testing.T) {
	previousAnchors := []*subject.SuffixAnchor{
		{Suffix: createSuffix},
		{Suffix: updateSuffix, Anchor: updatePrevAnchor},
	}

	builder := NewBuilder(generator.NewRegistry())

	t.Run("success - mixed model (create + update)", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       namespace,
			Version:         0,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
		}

		anchorLink, vcBytes, err := builder.BuildAnchorLink(payload, datauri.MediaTypeDataURIGzipBase64,
			func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error) {
				return &verifiable.Credential{}, nil
			},
		)
		require.NoError(t, err)
		require.NotEmpty(t, vcBytes)

		require.Equal(t, anchorOrigin, anchorLink.Author().String())

		require.NotNil(t, anchorLink.Related())

		relatedLinkset, err := anchorLink.Related().Linkset()
		require.NoError(t, err)
		require.NotNil(t, relatedLinkset.Link())
		// check parents (one item since we have one create and one update)
		require.Len(t, relatedLinkset.Link().Up(), 1)

		require.Equal(t, updatePrevAnchor, relatedLinkset.Link().Up()[0].String())

		contentObjBytes, err := anchorLink.Original().Content()
		require.NoError(t, err)

		t.Logf("Content: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonContentObj), string(contentObjBytes))
	})

	t.Run("error - no previous anchors", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:    coreIndex,
			Namespace:    namespace,
			Version:      0,
			AnchorOrigin: anchorOrigin,
		}

		_, err := builder.buildContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing previous anchors")
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		invalidPayload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       "did:other",
			Version:         0,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			OperationCount:  uint64(len(previousAnchors)),
		}

		contentObj, err := builder.buildContentObject(invalidPayload)
		require.Error(t, err)
		require.Nil(t, contentObj)
		require.Contains(t, err.Error(), "generator not found for namespace [did:other] and version [0]")
	})
}

func TestGetPayloadFromActivity(t *testing.T) {
	previousAnchors := []*subject.SuffixAnchor{
		{Suffix: createSuffix},
		{Suffix: updateSuffix, Anchor: updatePrevAnchor},
	}

	inPayload := &subject.Payload{
		CoreIndex:       coreIndex,
		Namespace:       namespace,
		Version:         0,
		AnchorOrigin:    anchorOrigin,
		PreviousAnchors: previousAnchors,
		OperationCount:  uint64(len(previousAnchors)),
	}

	builder := NewBuilder(generator.NewRegistry())

	t.Run("success - from payload", func(t *testing.T) {
		anchorLink, _, err := builder.BuildAnchorLink(inPayload, datauri.MediaTypeDataURIGzipBase64,
			func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error) {
				return &verifiable.Credential{}, nil
			},
		)
		require.NoError(t, err)

		outPayload, err := builder.GetPayloadFromAnchorLink(anchorLink)
		require.NoError(t, err)

		require.Equal(t, inPayload.Namespace, outPayload.Namespace)
		require.Equal(t, inPayload.Version, outPayload.Version)
		require.Equal(t, inPayload.AnchorOrigin, outPayload.AnchorOrigin)
		require.Equal(t, inPayload.CoreIndex, outPayload.CoreIndex)
		require.Equal(t, inPayload.PreviousAnchors, outPayload.PreviousAnchors)
		require.Equal(t, inPayload.OperationCount, outPayload.OperationCount)
	})

	t.Run("error - missing anchor object", func(t *testing.T) {
		payload, err := builder.GetPayloadFromAnchorLink(&linkset.Link{})
		require.EqualError(t, err, "get generator: nil generator URI")
		require.Nil(t, payload)
	})

	t.Run("error - invalid generator", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		err := json.Unmarshal([]byte(invalidProfile), &anchorLinkset)
		require.NoError(t, err)
		require.NotNil(t, anchorLinkset.Link())

		payload, err := builder.GetPayloadFromAnchorLink(anchorLinkset.Link())
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "generator not found")
	})

	t.Run("error - previous anchor not found in 'related' Linkset", func(t *testing.T) {
		anchorLinkset := &linkset.Linkset{}
		err := json.Unmarshal([]byte(invalidAnchorLinksetNoURN), &anchorLinkset)
		require.NoError(t, err)
		require.NotNil(t, anchorLinkset.Link())

		payload, err := builder.GetPayloadFromAnchorLink(anchorLinkset.Link())
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "failed to parse previous anchors")
	})
}

const (
	//nolint:lll
	invalidAnchorLinksetNoURN = `{
  "linkset": [
    {
      "anchor": "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%22%2C%22author%22%3A%22https%3A%2F%2Forb.domain1.com%2Fservices%2Forb%22%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDXvAb7xkkj8QleSnrt1sWah5lGT7MlGIYLNOmeILCoNA%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDljSIyFmQfONMeWRuXaAK7Veh0FDUsqtMu_FuWRes72g%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDJ0RDNSlRAe-X00jInBus3srtOwKDjkPhBScsCocAomQ%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiAcIEwYOvzu9JeDgi3tZPDvx4NOH5mgRKDax1o199_9QA%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA%22%2C%22previous%22%3A%5B%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiDfKmNhXjZBT9pi_ddpLRSp85p8jCTgMcHwEsW8C6xBVQ%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiBVjbmP2rO3zo0Dha94KivlGuBUINdyWvrpwHdC3xgGAA%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%3AEiBK9-TmD1pxSCBNfBYV5Ww6YZbQHH1ZZo5go2WpQ2_2GA%22%2C%22previous%22%3A%5B%22hl%3AuEiC_17B7wGGQ61SZi2QDQMpQcB-cqLZz1mdBOPcT3cAZBA%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%3AEiBS7BB7sgLlHkgX1wSQVYShaOPumObH2xieRnYA3CpIjA%22%2C%22previous%22%3A%5B%22hl%3AuEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ%22%5D%7D%2C%7B%22href%22%3A%22did%3Aorb%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AEiCmKxvTAtorz91jOPl-jCHMdCU2C_C96fqgc5nR3bbS4g%22%2C%22previous%22%3A%5B%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%22%5D%7D%5D%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%2C%22up%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiC6PTR6rRVbrvx2g06lYRwBDwWvO-8ZZdqBuvXUvYgBWg%3AuoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzZQVFI2clJWYnJ2eDJnMDZsWVJ3QkR3V3ZPLThaWmRxQnV2WFV2WWdCV2d4QmlwZnM6Ly9iYWZrcmVpZjJodTJodmxpdmxveHB5NXVkajJzd2NoYWJiNGMyNm83cGRmczV2YW4yNnhrbDNjYWJsaQ%22%7D%5D%7D%5D%7D",
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

	//nolint:lll
	invalidProfile = `{
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
      "profile": "https://w3id.org/xxxxx#v0",
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

	//nolint:lll
	jsonContentObj = `{
  "linkset": [
    {
      "anchor": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg",
      "author": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
      "item": [
        {
          "href": "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
        },
        {
          "href": "did:orb:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previous": [
            "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
          ]
        }
      ],
      "profile": "https://w3id.org/orb#v0"
    }
  ]
}`
)
