/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o nodeinforetriever.gen.go --fake-name NodeInfoRetriever . nodeInfoRetriever

func TestNewHandler(t *testing.T) {
	t.Run("V2.0", func(t *testing.T) {
		h := NewHandler(V2_0, &NodeInfoRetriever{}, nil)
		require.NotNil(t, h)
		require.Equal(t, http.MethodGet, h.Method())
		require.Equal(t, "/nodeinfo/2.0", h.Path())
		require.NotNil(t, h.Handler())
	})

	t.Run("V2.1", func(t *testing.T) {
		h := NewHandler(V2_1, &NodeInfoRetriever{}, nil)
		require.NotNil(t, h)
		require.Equal(t, http.MethodGet, h.Method())
		require.Equal(t, "/nodeinfo/2.1", h.Path())
		require.NotNil(t, h.Handler())
	})
}

func TestHandlerV2_0(t *testing.T) {
	nodeInfo := &NodeInfo{
		Version:   V2_0,
		Protocols: []string{activityPubProtocol},
		Software: Software{
			Name:    "Orb",
			Version: OrbVersion,
		},
		Services: Services{
			Inbound:  []string{},
			Outbound: []string{},
		},
		OpenRegistrations: false,
		Usage: Usage{
			Users: Users{
				Total: 1,
			},
			LocalPosts:    10,
			LocalComments: 5,
		},
	}

	testHandler(t, V2_0, nodeInfo, nodeInfoV2_0Response)
}

func TestHandlerV2_1(t *testing.T) {
	nodeInfo := &NodeInfo{
		Version:   V2_1,
		Protocols: []string{activityPubProtocol},
		Software: Software{
			Name:       "Orb",
			Version:    OrbVersion,
			Repository: orbRepository,
		},
		Services: Services{
			Inbound:  []string{},
			Outbound: []string{},
		},
		OpenRegistrations: false,
		Usage: Usage{
			Users: Users{
				Total: 1,
			},
			LocalPosts:    10,
			LocalComments: 5,
		},
	}

	testHandler(t, V2_1, nodeInfo, nodeInfoV2_1Response)
}

func TestNewHandlerError(t *testing.T) {
	t.Run("Marshal error", func(t *testing.T) {
		h := NewHandler(V2_0, &NodeInfoRetriever{}, nil)
		require.NotNil(t, h)

		errExpected := errors.New("injected marshal error")

		h.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://example.com/nodeinfo", nil)

		h.handle(rw, req)

		result := rw.Result()
		require.Equal(t, http.StatusInternalServerError, result.StatusCode)

		respBytes, err := ioutil.ReadAll(result.Body)
		require.NoError(t, err)

		t.Logf("%s", respBytes)

		require.Equal(t, internalServerErrorResponse, string(respBytes))
		require.NoError(t, result.Body.Close())
	})
}

func testHandler(t *testing.T, version Version, nodeInfo *NodeInfo, expected string) {
	t.Helper()

	retriever := &NodeInfoRetriever{}
	retriever.GetNodeInfoReturns(nodeInfo)

	h := NewHandler(version, retriever, nil)
	require.NotNil(t, h)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/nodeinfo", nil)

	h.handle(rw, req)

	result := rw.Result()
	require.Equal(t, http.StatusOK, result.StatusCode)

	respBytes, err := ioutil.ReadAll(result.Body)
	require.NoError(t, err)

	t.Logf("%s", respBytes)

	require.Equal(t, testutil.GetCanonical(t, expected), testutil.GetCanonical(t, string(respBytes)))
	require.NoError(t, result.Body.Close())
}

const (
	nodeInfoV2_0Response = `{
  "version": "2.0",
  "software": {
    "name": "Orb",
    "version": "latest"
  },
  "protocols": [
    "activitypub"
  ],
  "services": {
    "inbound": [],
    "outbound": []
  },
  "openRegistrations": false,
  "usage": {
    "users": {
      "total": 1
    },
    "localPosts": 10,
    "localComments": 5
  }
}`

	nodeInfoV2_1Response = `{
  "version": "2.1",
  "software": {
    "name": "Orb",
    "version": "latest",
    "repository": "https://github.com/trustbloc/orb"
  },
  "protocols": [
    "activitypub"
  ],
  "services": {
    "inbound": [],
    "outbound": []
  },
  "openRegistrations": false,
  "usage": {
    "users": {
      "total": 1
    },
    "localPosts": 10,
    "localComments": 5
  }
}`
)
