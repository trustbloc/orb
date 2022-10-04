/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	apmocks "github.com/trustbloc/orb/pkg/activitypub/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/store/cas"
)

const casLink = "https://domain.com/cas"

type failingResponseWriter struct{}

func (f *failingResponseWriter) Header() http.Header {
	return nil
}

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("response write failure")
}

func (f *failingResponseWriter) WriteHeader(int) {}

func TestWriteResponseFailures(t *testing.T) {
	t.Run("Fail to write failure response", func(t *testing.T) {
		t.Run("Status not found", func(t *testing.T) {
			casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{
				ErrGet: ariesstorage.ErrDataNotFound,
			}}, casLink, nil, &orbmocks.MetricsProvider{}, 0)

			require.NoError(t, err)

			webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
				&apmocks.AuthTokenMgr{})

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)
		})
		t.Run("Internal server error", func(t *testing.T) {
			casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

			require.NoError(t, err)

			webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
				&apmocks.AuthTokenMgr{})

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)
		})
	})
	t.Run("Fail to write success response", func(t *testing.T) {
		casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{}}, casLink, nil,
			&orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
			&apmocks.AuthTokenMgr{})

		rw := &failingResponseWriter{}
		req := httptest.NewRequest(http.MethodGet, "/cas", nil)

		webCAS.Handler()(rw, req)
	})
}
