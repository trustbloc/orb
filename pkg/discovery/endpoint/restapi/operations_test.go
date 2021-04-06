/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

const (
	wellKnownEndpoint = "/.well-known/did-orb"
)

func TestGetRESTHandlers(t *testing.T) {
	c := restapi.New(&restapi.Config{})
	require.Equal(t, 1, len(c.GetRESTHandlers()))
}

func TestWellKnown(t *testing.T) {
	c := restapi.New(&restapi.Config{
		OperationPath:  "/op",
		ResolutionPath: "/resolve",
		BaseURL:        "http://base",
	},
	)

	handler := getHandler(t, c, wellKnownEndpoint)

	rr := serveHTTP(t, handler.Handler(), http.MethodGet, wellKnownEndpoint, nil)

	var w wellKnowResp

	require.Equal(t, http.StatusOK, rr.Code)

	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &w))
	require.Equal(t, w.OperationEndpoint, "http://base/op")
	require.Equal(t, w.ResolutionEndpoint, "http://base/resolve")
}

type wellKnowResp struct {
	ResolutionEndpoint string `json:"resolutionEndpoint"`
	OperationEndpoint  string `json:"operationEndpoint"`
}

//nolint:unparam
func serveHTTP(t *testing.T, handler common.HTTPRequestHandler, method, path string,
	req []byte) *httptest.ResponseRecorder {
	httpReq, err := http.NewRequest(
		method,
		path,
		bytes.NewBuffer(req),
	)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	handler(rr, httpReq)

	return rr
}

func getHandler(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *restapi.Operation, lookup string) common.HTTPHandler {
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
