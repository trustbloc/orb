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

	"github.com/trustbloc/orb/pkg/store/cas"
)

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

func TestWriteResponseFailures(t *testing.T) {
	t.Run("Fail to write failure response", func(t *testing.T) {
		t.Run("Status not found", func(t *testing.T) {
			casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{
				ErrGet: ariesstorage.ErrDataNotFound,
			}})
			require.NoError(t, err)

			testLogger := &stringLogger{}

			webCAS := WebCAS{
				casClient: casClient,
				logger:    testLogger,
			}

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)

			require.Equal(t, "failed to write error response. CAS error that led to this: "+
				"content not found. Response write error: response write failure", testLogger.log)
		})
		t.Run("Internal server error", func(t *testing.T) {
			casClient, err := cas.New(mem.NewProvider())
			require.NoError(t, err)

			testLogger := &stringLogger{}

			webCAS := WebCAS{
				casClient: casClient,
				logger:    testLogger,
			}

			rw := &failingResponseWriter{}
			req := httptest.NewRequest(http.MethodGet, "/cas", nil)

			webCAS.Handler()(rw, req)

			require.Equal(t, "failed to write error response. CAS error that led to this: "+
				"failed to get content from the underlying storage provider: key cannot be empty. "+
				"Response write error: response write failure", testLogger.log)
		})
	})
	t.Run("Fail to write success response", func(t *testing.T) {
		casClient, err := cas.New(&mock.Provider{OpenStoreReturn: &mock.Store{}})
		require.NoError(t, err)

		testLogger := &stringLogger{}

		webCAS := WebCAS{
			casClient: casClient,
			logger:    testLogger,
		}

		rw := &failingResponseWriter{}
		req := httptest.NewRequest(http.MethodGet, "/cas", nil)

		webCAS.Handler()(rw, req)

		require.Equal(t, "failed to write success response: response write failure", testLogger.log)
	})
}
