/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aoprovider

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	coremocks "github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/orbclient/mocks"
	"github.com/trustbloc/orb/pkg/orbclient/protocol/nsprovider"
)

const testDID = "did"

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		client, err := New("did:orb", coremocks.NewMockCasClient(nil),
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)
		require.NotNil(t, client)
	})
	t.Run("success - with protocol versions", func(t *testing.T) {
		client, err := New("did:orb", coremocks.NewMockCasClient(nil),
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			WithProtocolVersions([]string{v1}),
			WithCurrentProtocolVersion(v1))
		require.NoError(t, err)
		require.NotNil(t, client)
	})
	t.Run("error - protocol version not supported", func(t *testing.T) {
		client, err := New("did:orb", coremocks.NewMockCasClient(nil),
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			WithProtocolVersions([]string{"0.1"}))
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), "client version factory for version [0.1] not found")
	})
	t.Run("error - protocol versions not provided", func(t *testing.T) {
		client, err := New("did:orb", coremocks.NewMockCasClient(nil),
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)),
			WithProtocolVersions([]string{}))
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), "must provide at least one client version")
	})
}

func TestGetAnchorOrigin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		previousDIDTxns := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload := subject.Payload{
			OperationCount:  2,
			CoreIndex:       "hl:uEiCHyWu0mRjSGe1OH6y545ALCHakBKr6E5vdVk4Re4qgdg",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		linksetBytes, err := json.Marshal(newMockAnchorLinkset(t, &payload))
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(linksetBytes)
		require.NoError(t, err)

		client, err := New("did:orb", casClient,
			WithPublicKeyFetcher(pubKeyFetcherFnc),
			WithJSONLDDocumentLoader(testutil.GetLoader(t)))
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
			CoreIndex:       "hl:uEiCHyWu0mRjSGe1OH6y545ALCHakBKr6E5vdVk4Re4qgdg",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		linksetBytes, err := json.Marshal(newMockAnchorLinkset(t, &payload))
		require.NoError(t, err)

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(linksetBytes)
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
			CoreIndex:       "hl:uEiCHyWu0mRjSGe1OH6y545ALCHakBKr6E5vdVk4Re4qgdg",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(testutil.MarshalCanonical(t, newMockAnchorLinkset(t, &payload)))
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
			CoreIndex:       "hl:uEiCHyWu0mRjSGe1OH6y545ALCHakBKr6E5vdVk4Re4qgdg",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousDIDTxns,
		}

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(testutil.MarshalCanonical(t, newMockAnchorLinkset(t, &payload)))
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
			CoreIndex:       "hl:uEiCHyWu0mRjSGe1OH6y545ALCHakBKr6E5vdVk4Re4qgdg",
			Namespace:       "did:test",
			Version:         1,
			PreviousAnchors: previousDIDTxns,
		}

		casClient := coremocks.NewMockCasClient(nil)

		cid, err := casClient.Write(testutil.MarshalCanonical(t, newMockAnchorLinkset(t, &payload)))
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
		require.Contains(t, err.Error(), "unable to read anchor[non-existent] from CAS: not found")
	})
}

func newMockAnchorLinkset(t *testing.T, payload *subject.Payload) *linkset.Linkset {
	t.Helper()

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{"https://www.w3.org/2018/credentials/v1"},
		Subject: &builder.CredentialSubject{},
		Issuer:  verifiable.Issuer{ID: "http://orb.domain.com"},
		Issued:  &util.TimeWrapper{Time: time.Now()},
	}

	link, _, err := anchorlinkset.NewBuilder(
		generator.NewRegistry()).BuildAnchorLink(payload, datauri.MediaTypeDataURIGzipBase64,
		func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error) {
			return vc, nil
		},
	)
	require.NoError(t, err)

	return linkset.New(link)
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}
