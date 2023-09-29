/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package maintenance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"
)

func TestHandlerWrapper(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		const path = "/services/orb/inbox"

		w := NewMaintenanceWrapper(&mockHTTPHandler{
			path:   path,
			method: http.MethodPost,
		})
		require.NotNil(t, w)

		require.Equal(t, path, w.Path())
		require.Equal(t, http.MethodPost, w.Method())

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/services/orb/inbox", nil)

		w.Handler()(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)
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
