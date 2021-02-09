/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnclient

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/didtxnref/memdidtxnref"
	"github.com/trustbloc/orb/pkg/txngraph"
)

const (
	namespace = "did:sidetree"
)

func TestNew(t *testing.T) {
	var txnCh chan []string

	providers := &Providers{
		TxnGraph:  txngraph.New(nil, pubKeyFetcherFnc),
		DidTxns:   memdidtxnref.New(),
		TxnSigner: &mockTxnSigner{},
	}

	c := New(namespace, providers, txnCh)
	require.NotNil(t, c)
}

func TestClient_WriteAnchor(t *testing.T) {
	providers := &Providers{
		TxnGraph:  txngraph.New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc),
		DidTxns:   memdidtxnref.New(),
		TxnSigner: &mockTxnSigner{},
	}

	t.Run("success", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		const testDID = "did:method:abc"

		didTxns := memdidtxnref.New()
		err := didTxns.Add(testDID, "cid")
		require.NoError(t, err)

		c := New(namespace, providers, txnCh)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID}}, 1)
		require.NoError(t, err)
	})

	t.Run("error - cas error", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		const testDID = "did:method:abc"

		didTxns := memdidtxnref.New()
		err := didTxns.Add(testDID, "cid")
		require.NoError(t, err)

		casErr := errors.New("CAS Error")
		providersWithErr := &Providers{
			TxnGraph:  txngraph.New(mocks.NewMockCasClient(casErr), pubKeyFetcherFnc),
			DidTxns:   memdidtxnref.New(),
			TxnSigner: &mockTxnSigner{},
		}

		c := New(namespace, providersWithErr, txnCh)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID}}, 1)
		require.Equal(t, err, casErr)
	})

	t.Run("error - sign error", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		const testDID = "did:method:abc"

		didTxns := memdidtxnref.New()
		err := didTxns.Add(testDID, "cid")
		require.NoError(t, err)

		providersWithErr := &Providers{
			TxnGraph:  txngraph.New(mocks.NewMockCasClient(nil), pubKeyFetcherFnc),
			DidTxns:   memdidtxnref.New(),
			TxnSigner: &mockTxnSigner{Err: errors.New("sign error")},
		}

		c := New(namespace, providersWithErr, txnCh)

		err = c.WriteAnchor("anchor", []*operation.Reference{{UniqueSuffix: testDID}}, 1)
		require.Contains(t, err.Error(), "failed to sign anchor credential: sign error")
	})
}

func TestClient_Read(t *testing.T) {
	providers := &Providers{
		TxnGraph: txngraph.New(nil, pubKeyFetcherFnc),
		DidTxns:  memdidtxnref.New(),
	}

	t.Run("success", func(t *testing.T) {
		txnCh := make(chan []string, 100)

		c := New(namespace, providers, txnCh)

		more, entries := c.Read(-1)
		require.False(t, more)
		require.Empty(t, entries)
	})
}

type mockTxnSigner struct {
	Err error
}

func (m *mockTxnSigner) Sign(vc *verifiable.Credential) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return vc, nil
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}
