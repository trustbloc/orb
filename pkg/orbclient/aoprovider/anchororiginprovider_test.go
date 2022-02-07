/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aoprovider

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/compression"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/orbclient/mocks"
	"github.com/trustbloc/orb/pkg/orbclient/protocol/nsprovider"
)

const testDID = "did"

func TestGetAnchorOrigin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		aeBytes, err := newMockAnchorEvent(t, &payload).MarshalJSON()
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cp := compression.New()

		_, compressed, err := cp.Compress(aeBytes)
		require.NoError(t, err)

		cid, err := casClient.Write(compressed)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			WithCompressionProvider(compression.New()))
		require.NoError(t, err)

		createOp := &operation.AnchoredOperation{
			AnchorOrigin: "testOrigin",
			UniqueSuffix: testDID,
			Type:         operation.TypeCreate,
		}

		ops := []*operation.AnchoredOperation{createOp}

		opsProvider := &coremocks.OperationProvider{}
		opsProvider.GetTxnOperationsReturns(ops, nil)

		clientVer := &coremocks.ProtocolVersion{}
		clientVer.OperationProviderReturns(opsProvider)

		clientVerProvider := &mocks.ClientVersionProvider{}
		clientVerProvider.GetReturns(clientVer, nil)

		nsProvider := nsprovider.New()
		nsProvider.Add("did:orb", clientVerProvider)

		client.nsProvider = nsProvider

		origin, err := client.GetAnchorOrigin(cid, testDID)
		require.NoError(t, err)
		require.NotEmpty(t, origin)
	})

	t.Run("error - anchored operation is an 'update' operation", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		vcBytes, err := newMockAnchorEvent(t, &payload).MarshalJSON()
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(vcBytes)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithDisableProofCheck(true),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		updateOp := &operation.AnchoredOperation{
			AnchorOrigin: "testOrigin",
			UniqueSuffix: testDID,
			Type:         operation.TypeUpdate,
		}

		ops := []*operation.AnchoredOperation{updateOp}

		opsProvider := &coremocks.OperationProvider{}
		opsProvider.GetTxnOperationsReturns(ops, nil)

		clientVer := &coremocks.ProtocolVersion{}
		clientVer.OperationProviderReturns(opsProvider)

		clientVerProvider := &mocks.ClientVersionProvider{}
		clientVerProvider.GetReturns(clientVer, nil)

		nsProvider := nsprovider.New()
		nsProvider.Add("did:orb", clientVerProvider)

		client.nsProvider = nsProvider

		origin, err := client.GetAnchorOrigin(cid, testDID)
		require.Error(t, err)
		require.Empty(t, origin)
		require.Contains(t, err.Error(), "anchor origin is only available for 'create' and 'recover' operations")
	})

	t.Run("error - failed to get anchored operation for suffix", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		aeBytes, err := newMockAnchorEvent(t, &payload).MarshalJSON()
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(aeBytes)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithDisableProofCheck(true),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		clientVer := &coremocks.ProtocolVersion{}
		clientVer.OperationProviderReturns(&coremocks.OperationProvider{})

		clientVerProvider := &mocks.ClientVersionProvider{}
		clientVerProvider.GetReturns(clientVer, nil)

		nsProvider := nsprovider.New()
		nsProvider.Add("did:orb", clientVerProvider)

		client.nsProvider = nsProvider

		origin, err := client.GetAnchorOrigin(cid, testDID)
		require.Error(t, err)
		require.Empty(t, origin)
		require.Contains(t, err.Error(), "suffix[did] not found in anchored operations")
	})

	t.Run("error - failed to read core index file", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		aeBytes, err := newMockAnchorEvent(t, &payload).MarshalJSON()
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(aeBytes)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithDisableProofCheck(true),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		origin, err := client.GetAnchorOrigin(cid, testDID)
		require.Error(t, err)
		require.Empty(t, origin)
		require.Contains(t, err.Error(), "not found")
	})

	t.Run("error - protocol client error", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: testDID},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "coreIndex",
			Namespace:       "did:test",
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		aeBytes, err := newMockAnchorEvent(t, &payload).MarshalJSON()
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(aeBytes)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithDisableProofCheck(true),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		origin, err := client.GetAnchorOrigin(cid, testDID)
		require.Error(t, err)
		require.Empty(t, origin)
		require.Contains(t, err.Error(), "failed to get client versions for namespace [did:test]")
	})

	t.Run("error - anchor (cid) not found", func(t *testing.T) {
		casClient := coremocks.NewMockCasClient(nil)

		client, err := New("did:orb", casClient)
		require.NoError(t, err)

		origin, err := client.GetAnchorOrigin("non-existent", testDID)
		require.Error(t, err)
		require.Empty(t, origin)
		require.Contains(t, err.Error(), "unable to read CID[non-existent] from CAS: not found")
	})
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
		vocab.MustMarshalToDoc(vc))
	require.NoError(t, err)

	return act
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}
