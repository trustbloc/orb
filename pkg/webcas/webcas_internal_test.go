/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas

import (
	"errors"
	"fmt"
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

type stringLogger struct {
	log string
}

func (s *stringLogger) Errorf(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Infof(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Debugf(msg string, args ...interface{}) {
	s.log = fmt.Sprintf(msg, args...)
}

func TestWriteResponseFailures(t *testing.T) {
	t.Run("Fail to write failure response", func(t *testing.T) {
		t.Run("Status not found", func(t *testing.T) {
			casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{
				ErrGet: ariesstorage.ErrDataNotFound,
			}}, casLink, nil, &orbmocks.MetricsProvider{}, 0)

			require.NoError(t, err)

			testLogger := &stringLogger{}

			webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
				&apmocks.AuthTokenMgr{})
			webCAS.logger = testLogger

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)

			require.Equal(t, "failed to write error response. CAS error that led to this: "+
				"content not found. Response write error: response write failure", testLogger.log)
		})
		t.Run("Internal server error", func(t *testing.T) {
			casClient, err := cas.New(mem.NewProvider(), casLink, nil, &orbmocks.MetricsProvider{}, 0)

			require.NoError(t, err)

			testLogger := &stringLogger{}

			webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
				&apmocks.AuthTokenMgr{})
			webCAS.logger = testLogger

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)

			require.Equal(t, "failed to write error response. CAS error that led to this: "+
				"failed to get content from the local CAS provider: key cannot be empty. "+
				"Response write error: response write failure", testLogger.log)
		})
	})
	t.Run("Fail to write success response", func(t *testing.T) {
		casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{}}, casLink, nil,
			&orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		testLogger := &stringLogger{}

		webCAS := New(&resthandler.Config{}, memstore.New(""), &mocks.SignatureVerifier{}, casClient,
			&apmocks.AuthTokenMgr{})
		webCAS.logger = testLogger

		rw := &failingResponseWriter{}
		req := httptest.NewRequest(http.MethodGet, "/cas", nil)

		webCAS.Handler()(rw, req)

		require.Equal(t, "failed to write success response: response write failure", testLogger.log)
	})
}
