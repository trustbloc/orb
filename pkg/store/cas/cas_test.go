/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
	localcas "github.com/trustbloc/orb/pkg/store/cas"
)

const casLink = "https://domain.com/cas"

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := localcas.New(ariesmemstorage.NewProvider(), casLink, nil,
			&orbmocks.MetricsProvider{}, 0)

		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to store in underlying storage provider", func(t *testing.T) {
		provider, err := localcas.New(&ariesmockstorage.Provider{ErrOpenStore: errors.New("open store error")},
			casLink, nil, &orbmocks.MetricsProvider{}, 0)

		require.EqualError(t, err, "failed to open store in underlying storage provider: open store error")
		require.Nil(t, provider)
	})
}

func TestProvider_Write_Read(t *testing.T) {
	log.SetLevel("cas-store", log.DEBUG)

	pool, ipfsResource := startIPFSDockerContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(ipfsResource), "failed to purge IPFS resource")
	}()

	t.Run("Success", func(t *testing.T) {
		client := ipfs.New("localhost:5001", 5*time.Second, 0, &orbmocks.MetricsProvider{})

		provider, err := localcas.New(ariesmemstorage.NewProvider(), casLink, client,
			&orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		var hl string

		// IPFS may not be ready yet... retries here are in case it returns an error due to not being started up yet.
		err = backoff.Retry(func() error {
			var errWrite error
			hl, errWrite = provider.WriteWithCIDFormat([]byte("content"))

			return errWrite
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
		require.NoError(t, err)

		rs, err := hashlink.GetResourceHashFromHashLink(hl)
		require.NoError(t, err)

		require.NoError(t, err)
		require.Equal(t, "uEiDtcAK0OemshF8iNX2CK6wURHMPvbYBbT7JQyKXueyfcw", rs)

		content, err := provider.Read(rs)
		require.NoError(t, err)
		require.Equal(t, "content", string(content))
	})
	t.Run("Fail to put content bytes into underlying storage provider", func(t *testing.T) {
		provider, err := localcas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrPut: errors.New("put error"),
			},
		}, casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.EqualError(t, err, "failed to put content into underlying storage provider: put error")
		require.Equal(t, "", address)
	})
	t.Run("Fail to get content bytes from underlying storage provider", func(t *testing.T) {
		t.Run("Data not found", func(t *testing.T) {
			provider, err := localcas.New(&ariesmockstorage.Provider{
				OpenStoreReturn: &ariesmockstorage.Store{
					ErrGet: ariesstorage.ErrDataNotFound,
				},
			}, casLink, nil, &orbmocks.MetricsProvider{}, 0)
			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.Equal(t, err, orberrors.ErrContentNotFound)
			require.Nil(t, content)
		})
		t.Run("Other error", func(t *testing.T) {
			provider, err := localcas.New(&ariesmockstorage.Provider{
				OpenStoreReturn: &ariesmockstorage.Store{
					ErrGet: errors.New("get error"),
				},
			}, casLink, nil, &orbmocks.MetricsProvider{}, 0)

			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.EqualError(t, err, "failed to get content from the local CAS provider: get error")
			require.Nil(t, content)
		})
	})
	t.Run("Invalid CID version", func(t *testing.T) {
		client := ipfs.New("localhost:5001", 5*time.Second, 0, &orbmocks.MetricsProvider{})

		provider, err := localcas.New(ariesmemstorage.NewProvider(), casLink, client,
			&orbmocks.MetricsProvider{}, 0, extendedcasclient.WithCIDVersion(2))
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.Contains(t, err.Error(), "2 is not a supported CID version. It must be either 0 or 1")
		require.Equal(t, "", address)
	})
	t.Run("Fail to write to IPFS", func(t *testing.T) {
		client := ipfs.New("InvalidURL", 5*time.Second, 0, &orbmocks.MetricsProvider{})

		provider, err := localcas.New(ariesmemstorage.NewProvider(), casLink, client,
			&orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.Contains(t, err.Error(), `failed to put content into IPFS (but it was successfully stored in `+
			`the local storage provider): Post "http://InvalidURL/api/v0/add?cid-version=1": dial tcp:`)
		require.Empty(t, address)
	})
	t.Run("Local CAS write and read -> success", func(t *testing.T) {
		content1 := []byte("content1")
		content2 := []byte("content2")

		provider, err := localcas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				GetReturn: content1,
			},
		}, casLink, nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		// Should read from DB and save to cache.
		content, err := provider.Read("uEiDat0G2KJ59zMHtQjMMrhrMwrdVzoB5ws1dS1Nmyfdppg")
		require.NoError(t, err)
		require.Equal(t, content1, content)

		// Should read from cache.
		content, err = provider.Read("cid1")
		require.NoError(t, err)
		require.Equal(t, content1, content)

		// Should save to DB and cache.
		hl, err := provider.Write(content2)
		require.NoError(t, err)

		rh, err := hashlink.GetResourceHashFromHashLink(hl)
		require.NoError(t, err)

		require.Equal(t, "uEiDat0G2KJ59zMHtQjMMrhrMwrdVzoB5ws1dS1Nmyfdppg", rh)

		// Should read from cache.
		content, err = provider.Read(rh)
		require.NoError(t, err)
		require.Equal(t, content2, content)
	})

	t.Run("Empty content", func(t *testing.T) {
		provider, err := localcas.New(&ariesmockstorage.Provider{}, casLink,
			nil, &orbmocks.MetricsProvider{}, 0)
		require.NoError(t, err)

		address, err := provider.Write(nil)
		require.EqualError(t, err, "empty content")
		require.Empty(t, address)
	})
}

func startIPFSDockerContainer(t *testing.T) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err, "failed to create pool")

	var ipfsResource *dctest.Resource

	// If there's an IPFS container currently shutting down, the call below can fail, hence the retries.
	// (This happens if you run the "make unit-test" script and the container doesn't shut down quickly enough)
	err = backoff.Retry(func() error {
		ipfsResource, err = pool.RunWithOptions(&dctest.RunOptions{
			Repository: "ipfs/go-ipfs",
			Tag:        "master-2021-04-22-eea198f",
			PortBindings: map[dc.Port][]dc.PortBinding{
				"5001/tcp": {{HostIP: "", HostPort: "5001"}},
			},
		})

		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
	require.NoError(t, err, "Failed to start IPFS Docker image."+
		" This can happen if there is an IPFS container still running from a previous unit test run."+
		` Try "docker ps" from the command line and kill the old container if it's still running.`)

	return pool, ipfsResource
}
