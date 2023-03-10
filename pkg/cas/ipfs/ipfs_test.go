/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ipfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/cas/ipfs/mocks"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

//go:generate counterfeiter -o ./mocks/ipfsclient.gen.go --fake-name IPFSClient . ipfsClient

func TestNew(t *testing.T) {
	c := New("ipfs:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{})
	require.NotNil(t, c)
}

func TestWrite(t *testing.T) {
	log.SetLevel(logModule, log.DEBUG)

	t.Run("success", func(t *testing.T) {
		pool, ipfsResource := startIPFSDockerContainer(t)

		defer func() {
			require.NoError(t, pool.Purge(ipfsResource), "failed to purge IPFS resource")
		}()

		t.Run("v1 CIDs", func(t *testing.T) {
			cas := New("localhost:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{})
			require.NotNil(t, cas)

			var cid string

			// IPFS will need some time to start up, hence the need for retries.

			err := backoff.Retry(func() error {
				var err error
				cid, err = cas.WriteWithCIDFormat([]byte("content"))

				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
			require.NoError(t, err)
			require.Equal(t, "bafkreihnoabliopjvscf6irvpwbcxlauirzq7pnwafwt5skdekl3t3e7om", cid)

			read, err := cas.Read(cid)
			require.Nil(t, err)
			require.Equal(t, "content", string(read))
		})
		t.Run("v0 CIDs", func(t *testing.T) {
			cas := New("localhost:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{},
				extendedcasclient.WithCIDVersion(0))
			require.NotNil(t, cas)

			var cid string

			// IPFS will need some time to start up, hence the need for retries.

			err := backoff.Retry(func() error {
				var err error
				cid, err = cas.WriteWithCIDFormat([]byte("content"), extendedcasclient.WithCIDVersion(0))

				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
			require.NoError(t, err)
			require.Equal(t, "QmbSnCcHziqhjNRyaunfcCvxPiV3fNL3fWL8nUrp5yqwD5", cid)

			read, err := cas.Read(cid)
			require.Nil(t, err)
			require.Equal(t, "content", string(read))
		})

		t.Run("success - hashlink", func(t *testing.T) {
			cas := New("localhost:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{},
				extendedcasclient.WithCIDVersion(1))
			require.NotNil(t, cas)

			var cid string

			// IPFS will need some time to start up, hence the need for retries.

			err := backoff.Retry(func() error {
				var err error
				cid, err = cas.Write([]byte("content"))

				return err
			}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
			require.NoError(t, err)

			read, err := cas.Read(cid)
			require.Nil(t, err)
			require.Equal(t, "content", string(read))
		})
	})

	t.Run("error - invalid hashlink", func(t *testing.T) {
		cas := New("localhost:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{},
			extendedcasclient.WithCIDVersion(1))
		require.NotNil(t, cas)

		read, err := cas.Read("hl:abc")
		require.Error(t, err)
		require.Nil(t, read)
		require.Contains(t, err.Error(), "value[hl:abc] passed to ipfs reader is not CID and cannot be converted to CID")
	})

	t.Run("error - hashlink (content not found)", func(t *testing.T) {
		cas := New("localhost:5001", 20*time.Second, 0, &orbmocks.MetricsProvider{},
			extendedcasclient.WithCIDVersion(1))
		require.NotNil(t, cas)

		read, err := cas.Read("hl:uEiBGzo1CWjNplt9iSVJdU9B9vfCm7u1d5CvqYsNbuMVT7Q:uoQ-BeEJpcGZzOi8vYmFma3JlaWNnejJndWV3cnRuZ2xuNnlzamtqb3ZodWQ1eHh5a24zeG5seHNjeDJ0Y3lubjNycmt0NXU")
		require.Error(t, err)
		require.Nil(t, read)
		require.Contains(t, err.Error(), "http://localhost:5001/api/v0/cat?arg=bafkreicgz2guewrtngln6ysjkjovhud5xxykn3xnlxscx2tcynn3rrkt5u")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Error(t, err)
		require.Empty(t, cid)
	})

	t.Run("invalid CID version", func(t *testing.T) {
		cas := New("IPFS URL", 20*time.Second, 0, &orbmocks.MetricsProvider{},
			extendedcasclient.WithCIDVersion(2))
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Empty(t, cid)
		require.EqualError(t, err, "2 is not a supported CID version. It must be either 0 or 1")
	})

	t.Run("empty content", func(t *testing.T) {
		cas := New("IPFS URL", 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Write(nil)
		require.Empty(t, cid)
		require.EqualError(t, err, "empty content")
	})

	t.Run("reader error", func(t *testing.T) {
		ipfs := &mocks.IPFSClient{}

		errExpected := errors.New("injected reader error")

		ipfs.CatReturns(newMockReader([]byte("content")).withError(errExpected), nil)

		cas := newClient(ipfs, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Read("bafkreihnoabliopjvscf6irvpwbcxlauirzq7pnwafwt5skdekl3t3e7om")
		require.Empty(t, cid)
		require.EqualError(t, err, err.Error())
	})

	t.Run("null content returned", func(t *testing.T) {
		ipfs := &mocks.IPFSClient{}

		ipfs.CatReturns(newMockReader([]byte("null")), nil)

		cas := newClient(ipfs, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Read("bafkreihnoabliopjvscf6irvpwbcxlauirzq7pnwafwt5skdekl3t3e7om")
		require.Empty(t, cid)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
	})

	t.Run("fail to write since node (ipfs.io) doesn't support writes", func(t *testing.T) {
		cas := New("https://ipfs.io", 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Write([]byte("content"))
		require.Empty(t, cid)
		require.EqualError(t, err, "add: command not found. (Does this IPFS node support writes?)")
	})
}

func TestRead(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{}")
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		read, err := cas.Read("uEiAWradITyYpRGT3pMhcKfPL8kpJBGePjFjZOlS0zqAUqw")
		require.Nil(t, err)
		require.NotNil(t, read)
	})

	t.Run("error - internal server error", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Read("cid")
		require.Error(t, err)
		require.Empty(t, cid)
	})

	t.Run("error - context deadline exceeded (content not found)", func(t *testing.T) {
		ipfs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("context deadline exceeded"))
			require.NoError(t, err)
		}))
		defer ipfs.Close()

		cas := New(ipfs.URL, 20*time.Second, 0, &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, err := cas.Read("uEiAWradITyYpRGT3pMhcKfPL8kpJBGePjFjZOlS0zqAUqw")
		require.EqualError(t, err, "cat: context deadline exceeded: content not found")
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

type mockReader struct {
	io.Reader
	err error
}

func newMockReader(value []byte) *mockReader {
	return &mockReader{Reader: bytes.NewBuffer(value)}
}

func (r *mockReader) withError(err error) *mockReader {
	r.err = err

	return r
}

func (r *mockReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}

	return r.Reader.Read(p)
}

func (r *mockReader) Close() error {
	return nil
}
