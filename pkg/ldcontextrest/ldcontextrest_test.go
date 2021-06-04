/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontextrest

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	client, err := New(&mock.Provider{ErrOpenStore: errors.New("error")})
	require.Error(t, err)
	require.Nil(t, client)

	client, err = New(mem.NewProvider())
	require.NoError(t, err)
	require.NotNil(t, client)

	require.Equal(t, client.Path(), "/context/add")
	require.Equal(t, client.Method(), http.MethodPost)

	rw := &responseWriter{}
	client.Handler()(rw, &http.Request{Body: io.NopCloser(strings.NewReader(`{}`))})
	require.Equal(t, "{}\n", string(rw.data))

	rw = &responseWriter{}
	client.Handler()(rw, &http.Request{Body: io.NopCloser(strings.NewReader(`{"documents":[{}]}`))})
	require.Equal(t, "context URL is mandatory", string(rw.data))
}

type responseWriter struct {
	err  error
	data []byte
}

func (rw *responseWriter) Header() http.Header { return nil }
func (rw *responseWriter) WriteHeader(int)     {}
func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.data = b

	return len(rw.data), rw.err
}
