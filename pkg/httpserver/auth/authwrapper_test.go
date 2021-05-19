/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

func TestHandlerWrapper(t *testing.T) {
	cfg := Config{
		AuthTokensDef: []*TokenDef{
			{
				EndpointExpression: "/services/orb/outbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
			{
				EndpointExpression: "/services/orb/inbox",
				ReadTokens:         []string{"admin", "read"},
				WriteTokens:        []string{"admin"},
			},
		},
		AuthTokens: map[string]string{
			"read":  "READ_TOKEN",
			"admin": "ADMIN_TOKEN",
		},
	}

	w := NewHandlerWrapper(cfg, &mockHTTPHandler{
		path:   "/services/orb/outbox",
		method: http.MethodPost,
	})
	require.NotNil(t, w)

	t.Run("Success", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", nil)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		w.Handler()(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Unauthorized", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", nil)

		w.Handler()(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusUnauthorized, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})
}

type mockHTTPHandler struct {
	path   string
	method string
}

func (m *mockHTTPHandler) Path() string {
	return m.path
}

func (m *mockHTTPHandler) Method() string {
	return m.method
}

func (m *mockHTTPHandler) Handler() common.HTTPRequestHandler {
	return func(writer http.ResponseWriter, request *http.Request) {}
}
