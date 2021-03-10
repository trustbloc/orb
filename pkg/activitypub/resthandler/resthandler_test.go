/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
)

func TestNewHandler(t *testing.T) {
	const endpoint = "/services/orb"

	serviceIRI, err := url.Parse(serviceURL)
	require.NoError(t, err)

	h := newHandler(endpoint, serviceIRI, memstore.New(""),
		func(writer http.ResponseWriter, request *http.Request) {},
	)

	require.NotNil(t, h)
	require.Equal(t, endpoint, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
}

func getCanonical(t *testing.T, raw string) string {
	var expectedDoc map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(raw), &expectedDoc))

	bytes, err := canonicalizer.MarshalCanonical(expectedDoc)

	require.NoError(t, err)

	return string(bytes)
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}
