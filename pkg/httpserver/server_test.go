/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	vct2 "github.com/trustbloc/orb/pkg/vct"
)

const (
	url       = "localhost:8080"
	clientURL = "http://" + url

	samplePath = "/sample"
)

func TestServer_Start(t *testing.T) {
	s := New(url,
		"",
		"",
		time.Second,
		time.Second,
		&mockService{},
		&mockService{},
		&mockService{},
		&mockService{},
		&mockUpdateHandler{},
		&mockResolveHandler{},
	)
	require.NoError(t, s.Start())
	require.Error(t, s.Start())

	// Wait for the service to start
	time.Sleep(time.Second)

	t.Run("success - sample operation ", func(t *testing.T) {
		resp, err := httpPut(t, clientURL+samplePath, []byte(""))
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("success - sample resolution", func(t *testing.T) {
		resp, err := httpGet(t, clientURL+samplePath+"/id")
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("success - health check", func(t *testing.T) {
		b := &httptest.ResponseRecorder{}
		s.healthCheckHandler(b, nil)

		require.Equal(t, http.StatusOK, b.Code)
	})

	t.Run("error - health check", func(t *testing.T) {
		b := httptest.NewRecorder()
		s1 := New(url,
			"",
			"",
			time.Second,
			time.Second,
			&mockService{isConnectedErr: fmt.Errorf("not connected")},
			&mockService{healthCheckErr: fmt.Errorf("failed")},
			&mockService{pingErr: fmt.Errorf("failed")},
			&mockService{healthCheckErr: fmt.Errorf("failed")},
			&mockUpdateHandler{},
			&mockResolveHandler{},
		)
		s1.healthCheckHandler(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)

		resp := &healthCheckResp{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, "failed", resp.VCTStatus)
		require.Equal(t, "failed", resp.DBStatus)
		require.Equal(t, "failed", resp.KMSStatus)
		require.Equal(t, "not connected", resp.MQStatus)
	})

	t.Run("VCT disabled - health check", func(t *testing.T) {
		b := httptest.NewRecorder()
		s1 := New(url,
			"",
			"",
			time.Second,
			time.Second,
			&mockService{},
			&mockService{healthCheckErr: vct2.ErrDisabled},
			&mockService{},
			&mockService{},
			&mockUpdateHandler{},
			&mockResolveHandler{},
		)
		s1.healthCheckHandler(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		resp := &healthCheckResp{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, vct2.ErrDisabled.Error(), resp.VCTStatus)
		require.Equal(t, "success", resp.DBStatus)
		require.Equal(t, "success", resp.KMSStatus)
		require.Equal(t, "success", resp.MQStatus)
	})

	t.Run("VCT log endpoint not configured - health check", func(t *testing.T) {
		b := httptest.NewRecorder()
		s1 := New(url,
			"",
			"",
			time.Second,
			time.Second,
			&mockService{},
			&mockService{healthCheckErr: vct2.ErrLogEndpointNotConfigured},
			&mockService{},
			&mockService{},
			&mockUpdateHandler{},
			&mockResolveHandler{},
		)
		s1.healthCheckHandler(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusOK, result.StatusCode)

		resp := &healthCheckResp{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, vct2.ErrLogEndpointNotConfigured.Error(), resp.VCTStatus)
		require.Equal(t, "success", resp.DBStatus)
		require.Equal(t, "success", resp.KMSStatus)
		require.Equal(t, "success", resp.MQStatus)
	})

	t.Run("Unknown error - health check", func(t *testing.T) {
		b := httptest.NewRecorder()
		s1 := New(url,
			"",
			"",
			time.Second,
			time.Second,
			&mockService{isConnectedErr: fmt.Errorf("")},
			&mockService{healthCheckErr: fmt.Errorf("")},
			&mockService{pingErr: fmt.Errorf("")},
			&mockService{healthCheckErr: fmt.Errorf("")},
			&mockUpdateHandler{},
			&mockResolveHandler{},
		)
		s1.healthCheckHandler(b, nil)

		result := b.Result()

		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode)

		resp := &healthCheckResp{}

		require.NoError(t, json.NewDecoder(result.Body).Decode(resp))
		require.NoError(t, result.Body.Close())

		require.Equal(t, "unknown error", resp.VCTStatus)
		require.Equal(t, "unknown error", resp.DBStatus)
		require.Equal(t, "unknown error", resp.KMSStatus)
		require.Equal(t, "not connected", resp.MQStatus)
	})

	t.Run("Stop", func(t *testing.T) {
		require.NoError(t, s.Stop(context.Background()))
		require.Error(t, s.Stop(context.Background()))
	})
}

func TestServer_HealthCheckNoServices(t *testing.T) {
	s := New(url,
		"",
		"",
		time.Second,
		time.Second,
		nil,
		nil,
		nil,
		nil,
		&mockUpdateHandler{},
		&mockResolveHandler{},
	)
	require.NoError(t, s.Start())

	defer func() {
		require.NoError(t, s.Stop(context.Background()))
	}()

	// Wait for the service to start
	time.Sleep(time.Second)

	t.Run("success - health check", func(t *testing.T) {
		b := &httptest.ResponseRecorder{}
		s.healthCheckHandler(b, nil)

		require.Equal(t, http.StatusOK, b.Code)
	})
}

// httpPut sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response.
func httpPut(t *testing.T, url string, req []byte) ([]byte, error) {
	t.Helper()

	client := &http.Client{}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(req))
	require.NoError(t, err)

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)

	return handleHTTPResp(resp)
}

// httpGet send a regular GET request to the sidetree-node and expects 'side tree document' argument as a response.
func httpGet(t *testing.T, url string) ([]byte, error) {
	t.Helper()

	client := &http.Client{}

	httpReq, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	require.NoError(t, err)

	resp, err := invokeWithRetry(
		func() (response *http.Response, e error) {
			return client.Do(httpReq)
		},
	)
	require.NoError(t, err)

	return handleHTTPResp(resp)
}

func handleHTTPResp(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return nil, errors.New(string(body))
	}

	return body, nil
}

func invokeWithRetry(invoke func() (*http.Response, error)) (*http.Response, error) {
	remainingAttempts := 20

	for {
		resp, err := invoke()
		if err == nil {
			return resp, nil
		}

		remainingAttempts--
		if remainingAttempts == 0 {
			return nil, err
		}

		time.Sleep(100 * time.Millisecond)
	}
}

type mockUpdateHandler struct{}

// Path returns the context path.
func (h *mockUpdateHandler) Path() string {
	return samplePath
}

// Method returns the HTTP method.
func (h *mockUpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the handler.
func (h *mockUpdateHandler) Handler() common.HTTPRequestHandler {
	return func(writer http.ResponseWriter, request *http.Request) {
	}
}

type mockResolveHandler struct{}

// Path returns the context path.
func (h *mockResolveHandler) Path() string {
	return samplePath + "/{id}"
}

// Method returns the HTTP method.
func (h *mockResolveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the handler.
func (h *mockResolveHandler) Handler() common.HTTPRequestHandler {
	return func(writer http.ResponseWriter, request *http.Request) {
	}
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
