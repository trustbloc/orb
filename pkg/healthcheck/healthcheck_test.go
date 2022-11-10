/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package healthcheck

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	vct2 "github.com/trustbloc/orb/pkg/vct"
)

func TestServer_Start(t *testing.T) {
	t.Run("success - health check", func(t *testing.T) {
		handler := NewHandler(&mockService{}, &mockService{}, &mockService{}, &mockService{})

		b := &httptest.ResponseRecorder{}
		handler.checkHealth(b, nil)

		require.Equal(t, http.StatusOK, b.Code)
	})

	t.Run("error - health check", func(t *testing.T) {
		h := NewHandler(
			&mockService{isConnectedErr: fmt.Errorf("not connected")},
			&mockService{healthCheckErr: fmt.Errorf("failed")},
			&mockService{pingErr: fmt.Errorf("failed")},
			&mockService{healthCheckErr: fmt.Errorf("failed")},
		)

		b := httptest.NewRecorder()
		h.checkHealth(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)

		resp := &response{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, "failed", resp.VCTStatus)
		require.Equal(t, "failed", resp.DBStatus)
		require.Equal(t, "failed", resp.KMSStatus)
		require.Equal(t, "not connected", resp.MQStatus)
	})

	t.Run("VCT disabled - health check", func(t *testing.T) {
		h := NewHandler(
			&mockService{},
			&mockService{healthCheckErr: vct2.ErrDisabled},
			&mockService{},
			&mockService{},
		)

		b := httptest.NewRecorder()
		h.checkHealth(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		resp := &response{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, vct2.ErrDisabled.Error(), resp.VCTStatus)
		require.Equal(t, "success", resp.DBStatus)
		require.Equal(t, "success", resp.KMSStatus)
		require.Equal(t, "success", resp.MQStatus)
	})

	t.Run("VCT log endpoint not configured - health check", func(t *testing.T) {
		h := NewHandler(
			&mockService{},
			&mockService{healthCheckErr: vct2.ErrLogEndpointNotConfigured},
			&mockService{},
			&mockService{},
		)

		b := httptest.NewRecorder()
		h.checkHealth(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		resp := &response{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, vct2.ErrLogEndpointNotConfigured.Error(), resp.VCTStatus)
		require.Equal(t, "success", resp.DBStatus)
		require.Equal(t, "success", resp.KMSStatus)
		require.Equal(t, "success", resp.MQStatus)
	})

	t.Run("Unknown error - health check", func(t *testing.T) {
		h := NewHandler(
			&mockService{isConnectedErr: fmt.Errorf("")},
			&mockService{healthCheckErr: fmt.Errorf("")},
			&mockService{pingErr: fmt.Errorf("")},
			&mockService{healthCheckErr: fmt.Errorf("")},
		)

		b := httptest.NewRecorder()
		h.checkHealth(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)

		resp := &response{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, "unknown error", resp.VCTStatus)
		require.Equal(t, "unknown error", resp.DBStatus)
		require.Equal(t, "unknown error", resp.KMSStatus)
		require.Equal(t, "not connected", resp.MQStatus)
	})
}

func TestServer_HealthCheckNoServices(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil)

	b := &httptest.ResponseRecorder{}
	h.checkHealth(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

type mockService struct {
	isConnectedErr error
	healthCheckErr error
	pingErr        error
}

func (m *mockService) IsConnected() bool {
	return m.isConnectedErr == nil
}

func (m *mockService) HealthCheck() error {
	return m.healthCheckErr
}

func (m *mockService) Ping() error {
	return m.pingErr
}
