/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("success - defaults", func(t *testing.T) {
		c := New()

		require.NotNil(t, c.httpClient)
		require.Equal(t, 300*time.Second, c.cacheLifetime)
	})

	t.Run("success - options", func(t *testing.T) {
		c := New(WithHTTPClient(http.DefaultClient), WithCacheLifetime(5*time.Second))

		require.Equal(t, http.DefaultClient, c.httpClient)
		require.Equal(t, 5*time.Second, c.cacheLifetime)
	})
}

func TestGetLedgerType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)
	})

	t.Run("success - cache entry expired", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient), WithCacheLifetime(2*time.Second))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)

		lt, err = c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)

		// sleep for 3 seconds so that cache entry expires
		time.Sleep(3 * time.Second)

		lt, err = c.GetLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.Equal(t, "vct", lt)
	})

	t.Run("error - http.Do() error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("http.Do() error")
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "http.Do() error")
	})

	t.Run("error - ledger type not a string", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type": 100}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "ledger type 'float64' is not a string")
	})

	t.Run("error - no ledger type property", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "ledger type not found")
	})

	t.Run("error - resource not found", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString("not found")),
				StatusCode: http.StatusNotFound,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "ledger type not found")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString("internal server error"),
				),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))
		lt, err := c.GetLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.Empty(t, lt)
		require.Contains(t, err.Error(), "status code: 500 message: internal server error")
	})
}

func TestHasSupportedLedgerType(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct-v1"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.True(t, supported)
	})

	t.Run("success - ledger type not supported", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString(`{"properties":{"https://trustbloc.dev/ns/ledger-type":"vct"}}`),
				),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.False(t, supported)
	})

	t.Run("success - no ledger type not found", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusOK,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.NoError(t, err)
		require.False(t, supported)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		httpClient := httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body: ioutil.NopCloser(
					bytes.NewBufferString("internal server error"),
				),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})

		c := New(WithHTTPClient(httpClient))

		supported, err := c.HasSupportedLedgerType("https://orb.domain.com")
		require.Error(t, err)
		require.False(t, supported)
		require.Contains(t, err.Error(), "status code: 500 message: internal server error")
	})
}

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}
