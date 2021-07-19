/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ipfs

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
)

func TestNew(t *testing.T) {
	c := New("ipfs:5001", 5*time.Second)
	require.NotNil(t, c)
}

func TestWrite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		pool, ipfsResource := startIPFSDockerContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(ipfsResource), "failed to purge IPFS resource")
		}()

		t.Run("v1 CIDs", func(t *testing.T) {
			cas := New("localhost:5001", 5*time.Second)
			require.NotNil(t, cas)

			var cid string

			// IPFS will need some time to start up, hence the need for retries.

			err := backoff.Retry(func() error {
				var err error
				cid, err = cas.Write([]byte("content"))

				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
			require.NoError(t, err)
			require.Equal(t, "bafkreihnoabliopjvscf6irvpwbcxlauirzq7pnwafwt5skdekl3t3e7om", cid)

			read, err := cas.Read(cid)
			require.Nil(t, err)
			require.Equal(t, "content", string(read))
		})
		t.Run("v0 CIDs", func(t *testing.T) {
			cas := New("localhost:5001", 5*time.Second, extendedcasclient.WithCIDVersion(0))
			require.NotNil(t, cas)

			var cid string

			// IPFS will need some time to start up, hence the need for retries.

			err := backoff.Retry(func() error {
				var err error
				cid, err = cas.Write([]byte("content"))

				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
			require.NoError(t, err)
			require.Equal(t, "QmbSnCcHziqhjNRyaunfcCvxPiV3fNL3fWL8nUrp5yqwD5", cid)

			read, err := cas.Read(cid)
			require.Nil(t, err)
			require.Equal(t, "content", string(read))
		})
	})

	t.Run("error - internal server error", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 5*time.Second)
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Error(t, err)
		require.Empty(t, cid)
	})

	t.Run("invalid CID version", func(t *testing.T) {
		cas := New("IPFS URL", 5*time.Second, extendedcasclient.WithCIDVersion(2))
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Empty(t, cid)
		require.EqualError(t, err, "2 is not a supported CID version. It must be either 0 or 1")
	})
}

func TestRead(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{}")
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 5*time.Second)
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

		cas := New(ipfs.URL, 5*time.Second)
		require.NotNil(t, cas)

		cid, err := cas.Read("cid")
		require.Error(t, err)
		require.Empty(t, cid)
	})
}

func startIPFSDockerContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err, "failed to create pool")

	ipfsResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: "ipfs/go-ipfs",
		Tag:        "master-2021-04-22-eea198f",
		PortBindings: map[dc.Port][]dc.PortBinding{
			"5001/tcp": {{HostIP: "", HostPort: "5001"}},
		},
	})
	if err != nil {
		require.FailNow(t, "Failed to start IPFS Docker image."+
			" This can happen if there is an IPFS container still running from a previous unit test run."+
			` Try "docker ps" from the command line and kill the old container if it's still running.`)
	}

	return pool, ipfsResource
}
