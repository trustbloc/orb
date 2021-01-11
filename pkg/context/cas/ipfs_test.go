/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	c := New("ipfs:5001")
	require.NotNil(t, c)
}

func TestWrite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{}")
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL)
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Nil(t, err)

		read, err := cas.Read(cid)
		require.Nil(t, err)
		require.NotNil(t, read)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL)
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Error(t, err)
		require.Empty(t, cid)
	})
}

func TestRead(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{}")
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL)
		require.NotNil(t, cas)

		read, err := cas.Read("cid")
		require.Nil(t, err)
		require.NotNil(t, read)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL)
		require.NotNil(t, cas)

		cid, err := cas.Read("cid")
		require.Error(t, err)
		require.Empty(t, cid)
	})
}
