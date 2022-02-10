/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	testNS  = "did:orb"
	testDID = "abc"

	casLink = "https://domain.com/cas"

	nonExistent = "uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ"
)

func TestNew(t *testing.T) {
	graph := New(&Providers{})
	require.NotNil(t, graph)
}

func TestGraph_Add(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), casLink, nil, &metricsProvider{}, 0)
	require.NoError(t, err)

	providers := &Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https"),
			&metricsProvider{}),
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		hl, err := graph.Add(newDefaultMockAnchorEvent(t))
		require.NoError(t, err)
		require.NotEmpty(t, hl)
	})
}

func TestGraph_Read(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), casLink, nil, &metricsProvider{}, 0)

	require.NoError(t, err)

	providers := &Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https"),
			&metricsProvider{}),
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		hl, err := graph.Add(newDefaultMockAnchorEvent(t))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		vc, err := graph.Read(hl)
		require.NoError(t, err)

		payloadFromVC, err := anchorevent.GetPayloadFromAnchorEvent(vc)
		require.NoError(t, err)

		require.Equal(t, testNS, payloadFromVC.Namespace)
	})

	t.Run("error - anchor (cid) not found", func(t *testing.T) {
		graph := New(providers)

		anchorNode, err := graph.Read("non-existent")
		require.Error(t, err)
		require.Nil(t, anchorNode)
	})
}

func TestGraph_GetDidAnchors(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), casLink, nil, &metricsProvider{}, 0)

	require.NoError(t, err)

	providers := &Providers{
		CasWriter: casClient,
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https"),
			&metricsProvider{}),
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success - first did anchor (create), no previous did anchors", func(t *testing.T) {
		graph := New(providers)

		hl, err := graph.Add(newDefaultMockAnchorEvent(t))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		didAnchors, err := graph.GetDidAnchors(hl, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("success - previous anchor for did exists", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-1",
			Namespace:       testNS,
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		anchor1HL, err := graph.Add(newMockAnchorEvent(t, payload))
		require.NoError(t, err)
		require.NotEmpty(t, anchor1HL)

		previousDIDTxns = []*subject.SuffixAnchor{
			{Suffix: testDID, Anchor: anchor1HL},
		}

		payload = &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-2",
			Namespace:       testNS,
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		hl, err := graph.Add(newMockAnchorEvent(t, payload))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		didAnchors, err := graph.GetDidAnchors(hl, testDID)
		require.NoError(t, err)
		require.Equal(t, 2, len(didAnchors))
		require.Equal(t, anchor1HL, didAnchors[0].CID)
	})

	t.Run("success - cid referenced in previous anchor empty (create)", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex",
			Namespace:       testNS,
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		hl, err := graph.Add(newMockAnchorEvent(t, payload))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		didAnchors, err := graph.GetDidAnchors(hl, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("error - cid referenced in previous anchor not found", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := []*subject.SuffixAnchor{
			{
				Suffix: testDID,
				Anchor: "hl:" + nonExistent + ":metadata",
			},
		}

		payload := &subject.Payload{
			CoreIndex:       "coreIndex-2",
			Namespace:       testNS,
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		hl, err := graph.Add(newMockAnchorEvent(t, payload))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		didAnchors, err := graph.GetDidAnchors(hl, testDID)
		require.Error(t, err)
		require.Nil(t, didAnchors)
		require.Contains(t, err.Error(), "failed to read anchor event")
	})

	t.Run("error - cid referenced in previous anchor is invalid", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := []*subject.SuffixAnchor{
			{
				Suffix: testDID,
				Anchor: "hl:nonExistent:metadata",
			},
		}

		payload := &subject.Payload{
			CoreIndex:       "coreIndex-2",
			Namespace:       testNS,
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		hl, err := graph.Add(newMockAnchorEvent(t, payload))
		require.NoError(t, err)
		require.NotEmpty(t, hl)

		didAnchors, err := graph.GetDidAnchors(hl, testDID)
		require.Error(t, err)
		require.Nil(t, didAnchors)
		require.Contains(t, err.Error(), "not a valid multihash")
	})

	t.Run("error - head cid not found", func(t *testing.T) {
		graph := New(providers)

		anchors, err := graph.GetDidAnchors("hl:"+nonExistent, "did")
		require.Error(t, err)
		require.Nil(t, anchors)
		require.Contains(t, err.Error(), "failed to get data stored at uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ")
	})
}

func newDefaultMockAnchorEvent(t *testing.T) *vocab.AnchorEventType {
	t.Helper()

	previousAnchors := []*subject.SuffixAnchor{
		{Suffix: "suffix"},
	}

	payload := &subject.Payload{
		OperationCount:  1,
		CoreIndex:       "coreIndex",
		Namespace:       testNS,
		Version:         0,
		PreviousAnchors: previousAnchors,
	}

	return newMockAnchorEvent(t, payload)
}

func newMockAnchorEvent(t *testing.T, payload *subject.Payload) *vocab.AnchorEventType {
	t.Helper()

	contentObj, err := anchorevent.BuildContentObject(payload)
	require.NoError(t, err)

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Subject: &builder.CredentialSubject{},
		Issuer: verifiable.Issuer{
			ID: "http://orb.domain.com",
		},
		Issued: &util.TimeWrapper{Time: time.Now()},
	}

	act, err := anchorevent.BuildAnchorEvent(payload, contentObj.GeneratorID, contentObj.Payload,
		vocab.MustMarshalToDoc(vc), vocab.GzipMediaType)
	require.NoError(t, err)

	return act
}

type metricsProvider struct{}

func (m *metricsProvider) CASWriteTime(value time.Duration) {
}

func (m *metricsProvider) CASResolveTime(value time.Duration) {
}

func (m *metricsProvider) CASIncrementCacheHitCount() {
}

func (m *metricsProvider) CASReadTime(casType string, value time.Duration) {
}
