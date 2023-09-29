/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/driver/restapi"
)

const (
	resolveDIDEndpoint = "/1.0/identifiers/{id}"
)

func TestDIDResolve(t *testing.T) {
	t.Run("test did query string not exists", func(t *testing.T) {
		c := restapi.New(&restapi.Config{})

		handler := getHandler(t, c, resolveDIDEndpoint)

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, resolveDIDEndpoint, nil, nil)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "url param 'did' is missing")
	})

	t.Run("test error from read did", func(t *testing.T) {
		c := restapi.New(&restapi.Config{OrbVDR: &mockvdr.MockVDR{
			ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return nil, fmt.Errorf("failed to read did")
			},
		}})

		handler := getHandler(t, c, resolveDIDEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = "did1"

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, resolveDIDEndpoint, nil, urlVars)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to read did")
	})

	t.Run("test success", func(t *testing.T) {
		c := restapi.New(&restapi.Config{OrbVDR: &mockvdr.MockVDR{
			ReadFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
				return &did.DocResolution{DIDDocument: &did.Doc{ID: "did1"}}, nil
			},
		}})

		handler := getHandler(t, c, resolveDIDEndpoint)

		urlVars := make(map[string]string)
		urlVars["id"] = "did1"

		rr := serveHTTP(t, handler.Handler(), http.MethodGet, resolveDIDEndpoint, nil, urlVars)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "did1")
	})
}

func serveHTTP(t *testing.T, handler common.HTTPRequestHandler, method, path string,
	req []byte, urlVars map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()

	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req1 := mux.SetURLVars(httpReq, urlVars)

	handler(rr, req1)

	return rr
}

func getHandler(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	t.Helper()

	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	t.Helper()

	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
