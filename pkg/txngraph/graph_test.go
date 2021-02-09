/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txngraph

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/api/txn"
	"github.com/trustbloc/orb/pkg/vcutil"
)

const testDID = "did:method:abc"

func TestNew(t *testing.T) {
	graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)
	require.NotNil(t, graph)
}

func TestGraph_Add(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		payload := txn.Payload{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		cid, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, cid)
	})
}

func TestGraph_Read(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		payload := txn.Payload{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		txnCID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, txnCID)

		vc, err := graph.Read(txnCID)
		require.NoError(t, err)

		payloadFromVC, err := vcutil.GetTransactionPayload(vc)
		require.NoError(t, err)

		require.Equal(t, payload.Namespace, payloadFromVC.Namespace)
	})

	t.Run("error - transaction (cid) not found", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		txnNode, err := graph.Read("non-existent")
		require.Error(t, err)
		require.Nil(t, txnNode)
	})
}

func TestGraph_GetDidTransactions(t *testing.T) {
	t.Run("success - first did transaction (create), no previous did transaction", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		payload := txn.Payload{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		txnCID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, txnCID)

		didTxns, err := graph.GetDidTransactions(txnCID, testDID)
		require.NoError(t, err)
		require.Equal(t, 0, len(didTxns))
	})

	t.Run("success - previous transaction for did exists", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		payload := txn.Payload{
			AnchorString: "anchor-1",
			Namespace:    "namespace",
			Version:      1,
		}

		txn1CID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, txn1CID)

		testDID := "did:method:abc"

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = txn1CID

		payload = txn.Payload{
			AnchorString:         "anchor-2",
			Namespace:            "namespace",
			Version:              1,
			PreviousTransactions: previousDIDTxns,
		}

		txnCID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, txnCID)

		didTxns, err := graph.GetDidTransactions(txnCID, testDID)
		require.NoError(t, err)
		require.Equal(t, 1, len(didTxns))
		require.Equal(t, txn1CID, didTxns[0])
	})

	t.Run("error - cid referenced in previous transaction not found", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		testDID := "did:method:abc"

		previousDIDTxns := make(map[string]string)
		previousDIDTxns[testDID] = "non-existent"

		payload := txn.Payload{
			AnchorString:         "anchor-2",
			Namespace:            "namespace",
			Version:              1,
			PreviousTransactions: previousDIDTxns,
		}

		txnCID, err := graph.Add(buildCredential(payload))
		require.NoError(t, err)
		require.NotNil(t, txnCID)

		didTxns, err := graph.GetDidTransactions(txnCID, testDID)
		require.Error(t, err)
		require.Nil(t, didTxns)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - head cid not found", func(t *testing.T) {
		graph := New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc)

		txnNode, err := graph.GetDidTransactions("non-existent", "did")
		require.Error(t, err)
		require.Nil(t, txnNode)
		require.Contains(t, err.Error(), "not found")
	})
}

func buildCredential(payload txn.Payload) *verifiable.Credential {
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
