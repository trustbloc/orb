/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	casresolver "github.com/trustbloc/orb/pkg/cas/resolver"
	caswriter "github.com/trustbloc/orb/pkg/cas/writer"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/cas"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testSuffix = "suffix"
	testOrigin = "origin"

	namespace = "did:orb"
)

func TestNew(t *testing.T) {
	didOriginHandler := New(nil, nil, nil)
	require.NotNil(t, didOriginHandler)
	require.Equal(t, endpoint, didOriginHandler.Path())
	require.Equal(t, http.MethodGet, didOriginHandler.Method())
	require.NotNil(t, didOriginHandler.Handler())
}

func TestHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		createOp := &operation.AnchoredOperation{
			AnchorOrigin: testOrigin,
			UniqueSuffix: testSuffix,
			Type:         operation.TypeCreate,
		}

		ops := []*operation.AnchoredOperation{createOp}

		opsProvider := &mocks.OperationProvider{}
		opsProvider.GetTxnOperationsReturns(ops, nil)

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].OperationProviderReturns(opsProvider)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, cid)
		require.NoError(t, err)

		pcp := mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace, pc)

		didOriginHandler := New(store, pcp, anchorGraph)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusOK, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, testOrigin, string(respBytes))
	})

	t.Run("error - mismatch between did anchor store and anchor graph", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].OperationProviderReturns(&mocks.OperationProvider{})
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, cid)
		require.NoError(t, err)

		pcp := mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace, pc)

		didOriginHandler := New(store, pcp, anchorGraph)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})

	t.Run("error - did anchor of wrong type(not string)", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		createOp := &operation.AnchoredOperation{
			AnchorOrigin: []string{testOrigin},
			UniqueSuffix: testSuffix,
			Type:         operation.TypeCreate,
		}

		ops := []*operation.AnchoredOperation{createOp}

		opsProvider := &mocks.OperationProvider{}
		opsProvider.GetTxnOperationsReturns(ops, nil)

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].OperationProviderReturns(opsProvider)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, cid)
		require.NoError(t, err)

		pcp := mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace, pc)

		didOriginHandler := New(store, pcp, anchorGraph)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})

	t.Run("error - protocol operation provider error", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		opsProvider := &mocks.OperationProvider{}
		opsProvider.GetTxnOperationsReturns(nil, fmt.Errorf("operation provider error"))

		pc := mocks.NewMockProtocolClient()
		pc.Protocol.GenesisTime = 1
		pc.Versions[0].OperationProviderReturns(opsProvider)
		pc.Versions[0].ProtocolReturns(pc.Protocol)

		casClient, err := cas.New(mem.NewProvider())
		require.NoError(t, err)

		graphProviders := &graph.Providers{
			CasWriter: caswriter.New(casClient, ""),
			CasResolver: casresolver.New(casClient, nil, transport.New(&http.Client{},
				testutil.MustParseURL("https://example.com/keys/public-key"),
				transport.DefaultSigner(), transport.DefaultSigner()),
			),
			Pkf:       pubKeyFetcherFnc,
			DocLoader: testutil.GetLoader(t),
		}

		anchorGraph := graph.New(graphProviders)

		payload1 := subject.Payload{Namespace: namespace, Version: 1, CoreIndex: "core1"}

		cid, _, err := anchorGraph.Add(buildCredential(payload1))
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, cid)
		require.NoError(t, err)

		pcp := mocks.NewMockProtocolClientProvider().WithProtocolClient(namespace, pc)

		didOriginHandler := New(store, pcp, anchorGraph)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})

	t.Run("error - anchor graph error", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, "some-cid")
		require.NoError(t, err)

		didOriginHandler := New(store, nil, &mockAnchorGraph{Err: fmt.Errorf("anchor graph error")})
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})

	t.Run("error - anchor not found for suffix", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		didOriginHandler := New(store, nil, nil)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusNotFound, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, notFoundResponse, string(respBytes))
	})

	t.Run("error - store error", func(t *testing.T) {
		mockStore := &storemocks.Store{}
		mockStore.GetReturns(nil, fmt.Errorf("get error"))

		mockProvider := &storemocks.Provider{}
		mockProvider.OpenStoreReturns(mockStore, nil)

		store, err := didanchorstore.New(mockProvider)
		require.NoError(t, err)

		didOriginHandler := New(store, nil, nil)
		require.NotNil(t, didOriginHandler)

		router := mux.NewRouter()

		router.HandleFunc(didOriginHandler.Path(), didOriginHandler.Handler())

		testServer := httptest.NewServer(router)
		defer testServer.Close()

		response, err := http.DefaultClient.Get(testServer.URL + "/origin/" + testSuffix)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, response.Body.Close())
		}()

		require.Equal(t, http.StatusInternalServerError, response.StatusCode)

		respBytes, err := ioutil.ReadAll(response.Body)
		require.NoError(t, err)
		require.NotEmpty(t, respBytes)
		require.Equal(t, internalServerErrorResponse, string(respBytes))
	})
}

func buildCredential(payload subject.Payload) *verifiable.Credential {
	const defVCContext = "https://www.w3.org/2018/credentials/v1"

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: payload,
		Issuer: verifiable.Issuer{
			ID: "http://orb.domain1.com",
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	return vc
}

var pubKeyFetcherFnc = func(issuerID, keyID string) (*verifier.PublicKey, error) {
	return nil, nil
}

type mockAnchorGraph struct {
	Err error
}

func (m *mockAnchorGraph) GetDidAnchors(cid, suffix string) ([]graph.Anchor, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return nil, nil
}
