/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package graph

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/anchor/subject"
	vcutil "github.com/trustbloc/orb/pkg/anchor/util"
)

const testDID = "abc"

func TestNew(t *testing.T) {
	graph := New(&Providers{})
	require.NotNil(t, graph)
}

func TestGraph_Add(t *testing.T) {
	providers := &Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		payload := subject.Payload{
			OperationCount: 1,
			CoreIndex:      "coreIndex",
			Namespace:      "namespace",
			Version:        1,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)
	})
}

func TestGraph_Read(t *testing.T) {
	providers := &Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
	}

	t.Run("success", func(t *testing.T) {
		graph := New(providers)

		payload := subject.Payload{
			OperationCount: 2,
			CoreIndex:      "coreIndex",
			Namespace:      "namespace",
			Version:        1,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)

		vc, err := graph.Read(cid)
		require.NoError(t, err)

		payloadFromVC, err := vcutil.GetAnchorSubject(vc)
		require.NoError(t, err)

		require.Equal(t, payload.Namespace, payloadFromVC.Namespace)
	})

	t.Run("error - anchor (cid) not found", func(t *testing.T) {
		graph := New(providers)

		anchorNode, err := graph.Read("non-existent")
		require.Error(t, err)
		require.Nil(t, anchorNode)
	})
}

func TestGraph_GetDidAnchors(t *testing.T) {
	providers := &Providers{
		Cas: mocks.NewMockCasClient(nil),
		Pkf: pubKeyFetcherFnc,
	}

	t.Run("success - first did anchor (create), no previous did anchors", func(t *testing.T) {
		graph := New(providers)

		payload := subject.Payload{
			OperationCount: 1,
			CoreIndex:      "coreIndex",
			Namespace:      "namespace",
			Version:        1,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("success - previous anchor for did exists", func(t *testing.T) {
		graph := New(providers)

		payload := subject.Payload{
			OperationCount: 1,
			CoreIndex:      "coreIndex-1",
			Namespace:      "namespace",
			Version:        1,
		}

		anchor1CID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, anchor1CID)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = anchor1CID

		payload = subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-2",
			Namespace:       "namespace",
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 2, len(didAnchors))
		require.Equal(t, anchor1CID, didAnchors[0].CID)
	})

	t.Run("success - cid referenced in previous anchor empty (create)", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = ""

		payload := subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex-3",
			Namespace:       "namespace",
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)

		didAnchors, err := graph.GetDidAnchors(cid, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didAnchors))
	})

	t.Run("error - cid referenced in previous anchor not found", func(t *testing.T) {
		graph := New(providers)

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = "non-existent"

		payload := subject.Payload{
			CoreIndex:       "coreIndex-2",
			Namespace:       "namespace",
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)

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
		require.Contains(t, err.Error(), "not found")
	})
}

func buildCredential(payload subject.Payload) *verifiable.Credential {
	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: payload,
		Issuer: verifiable.Issuer{
			ID: "http://peer1.com",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	return vc
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}
