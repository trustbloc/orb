/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/anchor/activity"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	vcutil "github.com/trustbloc/orb/pkg/anchor/util"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	caswriter "github.com/trustbloc/orb/pkg/cas/writer"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	testNS  = "did:orb"
	testDID = "abc"
)

func TestNew(t *testing.T) {
	graph := New(&Providers{})
	require.NotNil(t, graph)
}

func TestGraph_Add(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), nil)
	require.NoError(t, err)

	providers := &Providers{
		CasWriter: caswriter.New(casClient, "webcas:domain.com"),
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https")),
		Pkf:       pubKeyFetcherFnc,
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		c, err := buildDefaultCredential()
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)
	})
}

func TestGraph_Read(t *testing.T) {
	casClient, err := cas.New(mem.NewProvider(), nil)
	require.NoError(t, err)

	providers := &Providers{
		CasWriter: caswriter.New(casClient, "ipfs"),
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https")),
		Pkf:       pubKeyFetcherFnc,
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		c, err := buildDefaultCredential()
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)

		vc, err := graph.Read(cid)
		require.NoError(t, err)

		payloadFromVC, err := vcutil.GetAnchorSubject(vc)
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
	casClient, err := cas.New(mem.NewProvider(), nil)
	require.NoError(t, err)

	providers := &Providers{
		CasWriter: caswriter.New(casClient, "webcas:domain.com"),
		CasResolver: casresolver.New(casClient, nil,
			casresolver.NewWebCASResolver(
				&apmocks.HTTPTransport{}, webfingerclient.New(), "https")),
		Pkf:       pubKeyFetcherFnc,
		DocLoader: testutil.GetLoader(t),
	}

	t.Run("success - first did anchor (create), no previous did anchors", func(t *testing.T) {
		graph := New(providers)

		c, err := buildDefaultCredential()
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("success - previous anchor for did exists", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = ""
		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-1",
			Namespace:       testNS,
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		c, err := buildCredential(payload)
		require.NoError(t, err)

		anchor1CID, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, anchor1CID)
		require.NotEmpty(t, hint)

		previousDIDTxns = make(map[string]string)
		previousDIDTxns[testDID] = anchor1CID

		payload = &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-2",
			Namespace:       testNS,
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		c, err = buildCredential(payload)
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 2, len(didAnchors))
		require.Equal(t, anchor1CID, didAnchors[0].CID)
	})

	t.Run("success - cid referenced in previous anchor empty (create)", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = ""

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex",
			Namespace:       testNS,
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		c, err := buildCredential(payload)
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("error - cid referenced in previous anchor not found", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = "non-existent"

		payload := &subject.Payload{
			CoreIndex:       "coreIndex-2",
			Namespace:       testNS,
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		c, err := buildCredential(payload)
		require.NoError(t, err)

		cid, hint, err := graph.Add(c)
		require.NoError(t, err)
		require.NotEmpty(t, cid)
		require.NotEmpty(t, hint)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.Error(t, err)
		require.Nil(t, didAnchors)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - head cid not found", func(t *testing.T) {
		graph := New(providers)

		anchors, err := graph.GetDidAnchors("non-existent", "did")
		require.Error(t, err)
		require.Nil(t, anchors)
		require.Contains(t, err.Error(), "failed to get data stored at non-existent")
	})
}

func buildDefaultCredential() (*verifiable.Credential, error) {
	previousAnchors := make(map[string]string)
	previousAnchors["suffix"] = ""

	payload := &subject.Payload{
		OperationCount:  1,
		CoreIndex:       "coreIndex",
		Namespace:       testNS,
		Version:         1,
		PreviousAnchors: previousAnchors,
	}

	return buildCredential(payload)
}

func buildCredential(payload *subject.Payload) (*verifiable.Credential, error) {
	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	act, err := activity.BuildActivityFromPayload(payload)
	if err != nil {
		return nil, err
	}

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: act,
		Issuer: verifiable.Issuer{
			ID: "http://orb.domain.com",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	return vc, nil
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}
