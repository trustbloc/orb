/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package remoteresolver

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/mocks"
)

const (
	id = "abc"
)

func TestNew(t *testing.T) {
	endpoints := []string{"https://domain.com/identifiers"}

	t.Run("success", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("{}"))
		require.NoError(t, err)

		result := rw.Result()
		result.Header.Set("Content-type", didLDJson)

		httpClient.GetReturns(result, nil)

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.NoError(t, err)
		require.NotNil(t, rr)

		require.NoError(t, result.Body.Close())
	})

	t.Run("error  - unmarshal resolution result error", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("invalid-json"))
		require.NoError(t, err)

		result := rw.Result()
		result.Header.Set("Content-type", didLDJson)

		httpClient.GetReturns(result, nil)

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(),
			"failed to unmarshal resolution result[invalid-json] for remote request[https://domain.com/identifiers/abc]")

		require.NoError(t, result.Body.Close())
	})

	t.Run("error - missing endpoints", func(t *testing.T) {
		resolver := New(&mocks.HTTPTransport{})
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, []string{})
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "must provide at least one remote resolver endpoint in order to retrieve data")
	})

	t.Run("error - HTTP Get error", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}
		httpClient.GetReturns(nil, fmt.Errorf("HTTP Get Error"))

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "failed to execute GET call on https://domain.com/identifiers/abc: HTTP Get Error")
	})

	t.Run("error - invalid HTTP status returned", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("Internal server error."))
		require.NoError(t, err)

		result := rw.Result()
		result.StatusCode = 500

		httpClient.GetReturns(result, nil)

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "Response status code: 500")

		require.NoError(t, result.Body.Close())
	})

	t.Run("error - 404 HTTP status returned", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("Not found."))
		require.NoError(t, err)

		result := rw.Result()
		result.StatusCode = 404

		httpClient.GetReturns(result, nil)

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "data not found for request")

		require.NoError(t, result.Body.Close())
	})

	t.Run("error - wrong content type returned", func(t *testing.T) {
		httpClient := &mocks.HTTPTransport{}

		rw := httptest.NewRecorder()

		_, err := rw.Write([]byte("{}"))
		require.NoError(t, err)

		result := rw.Result()

		httpClient.GetReturns(result, nil)

		resolver := New(httpClient)
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, endpoints)
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "Content-type: text/plain")

		require.NoError(t, result.Body.Close())
	})

	t.Run("error - failed to parse endpoint URL", func(t *testing.T) {
		resolver := New(&mocks.HTTPTransport{})
		require.NotNil(t, resolver)

		rr, err := resolver.ResolveDocumentFromResolutionEndpoints(id, []string{"!!!:"})
		require.Error(t, err)
		require.Nil(t, rr)
		require.Contains(t, err.Error(), "failed to parse request URL")
	})
}
