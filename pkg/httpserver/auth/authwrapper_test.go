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
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
)

func TestHandlerWrapper(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		w := NewHandlerWrapper(&mockHTTPHandler{
			path:   "/services/orb/outbox",
			method: http.MethodPost,
		}, &apmocks.AuthTokenMgr{})
		require.NotNil(t, w)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", http.NoBody)
		req.Header[authHeader] = []string{tokenPrefix + "ADMIN_TOKEN"}

		w.Handler()(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusOK, result.StatusCode)
		require.NoError(t, result.Body.Close())
	})

	t.Run("Unauthorized", func(t *testing.T) {
		tm := &apmocks.AuthTokenMgr{}
		tm.RequiredAuthTokensReturns([]string{"admin"}, nil)

		w := NewHandlerWrapper(&mockHTTPHandler{
			path:   "/services/orb/outbox",
			method: http.MethodPost,
		}, tm)
		require.NotNil(t, w)

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/services/orb/outbox", http.NoBody)

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
