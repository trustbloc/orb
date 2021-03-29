/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ./mocks/httpclient.gen.go --fake-name HTTPClient . httpClient

func TestClient_GetActor(t *testing.T) {
	actorIRI := testutil.MustParseURL("https://example.com/services/service1")

	actorBytes, err := json.Marshal(aptestutil.NewMockService(actorIRI))
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		httpClient := &mocks.HTTPClient{}

		rw := httptest.NewRecorder()

		_, err = rw.Write(actorBytes)
		require.NoError(t, err)

		result := rw.Result()

		httpClient.DoReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.NoError(t, e)
		require.NotNil(t, actor)
		require.Equal(t, actorIRI.String(), actor.ID().String())

		require.NoError(t, result.Body.Close())
	})

	t.Run("Error status code", func(t *testing.T) {
		httpClient := &mocks.HTTPClient{}

		rw := httptest.NewRecorder()

		rw.Code = http.StatusInternalServerError

		result := rw.Result()

		httpClient.DoReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Nil(t, actor)
		require.Contains(t, e.Error(), "status code 500")

		require.NoError(t, result.Body.Close())
	})

	t.Run("HTTP client error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected HTTP client error")

		httpClient := &mocks.HTTPClient{}

		httpClient.DoReturns(nil, errExpected)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, e := c.GetActor(actorIRI)
		require.Error(t, e)
		require.Contains(t, e.Error(), errExpected.Error())
		require.Nil(t, actor)
	})

	t.Run("Unmarshal client error", func(t *testing.T) {
		rw := httptest.NewRecorder()

		_, err = rw.Write([]byte("{"))
		require.NoError(t, err)

		httpClient := &mocks.HTTPClient{}

		result := rw.Result()

		httpClient.DoReturns(result, nil)

		c := New(httpClient)
		require.NotNil(t, t, c)

		actor, err := c.GetActor(actorIRI)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
		require.Nil(t, actor)

		require.NoError(t, result.Body.Close())
	})
}
