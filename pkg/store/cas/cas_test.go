/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	ipfsshell "github.com/ipfs/go-ipfs-api"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	localcas "github.com/trustbloc/orb/pkg/store/cas"
)

const sampleAnchorCredential = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1",
    "https://w3id.org/jws/v1"
  ],
  "id": "http://sally.example.com/transactions/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
  "type": [
    "VerifiableCredential",
    "AnchorCredential"
  ],
  "issuer": "https://sally.example.com/services/orb",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
    "operationCount": 1,
    "coreIndex": "bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
    "namespace": "did:orb",
    "version": "1",
    "previousAnchors": {
      "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrmenuxhgaomod4m26ds5ztdujxzhjobgvpsyl2v2ndcskq2iay",
      "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3whnisud76knkv7z7ucbf3k2rs6knhvajernrdabdbfaomakli"
    },
    "type": "Anchor"
  },
  "proof": [{
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:00Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "sally.example.com",
    "jws": "eyJ..."
  },
  {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:05Z",
    "verificationMethod": "did:example:abcd#key",
    "domain": "https://witness1.example.com/ledgers/maple2021",
    "jws": "eyJ..."
  },
  {
    "type": "JsonWebSignature2020",
    "proofPurpose": "assertionMethod",
    "created": "2021-01-27T09:30:06Z",
    "verificationMethod": "did:example:efgh#key",
    "domain": "https://witness2.example.com/ledgers/spruce2021",
    "jws": "eyJ..."
  }]                  
}`

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := localcas.New(ariesmemstorage.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Fail to store in underlying storage provider", func(t *testing.T) {
		provider, err := localcas.New(&ariesmockstorage.Provider{ErrOpenStore: errors.New("open store error")})
		require.EqualError(t, err, "failed to open store in underlying storage provider: open store error")
		require.Nil(t, provider)
	})
}

func TestProvider_Write_Read(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider, err := localcas.New(ariesmemstorage.NewProvider())
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.NoError(t, err)
		require.Equal(t, "bafkreihnoabliopjvscf6irvpwbcxlauirzq7pnwafwt5skdekl3t3e7om", address)

		content, err := provider.Read(address)
		require.NoError(t, err)
		require.Equal(t, "content", string(content))
	})
	t.Run("Fail to put content bytes into underlying storage provider", func(t *testing.T) {
		provider, err := localcas.New(&ariesmockstorage.Provider{
			OpenStoreReturn: &ariesmockstorage.Store{
				ErrPut: errors.New("put error"),
			},
		})
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
			})
			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.Equal(t, err, localcas.ErrContentNotFound)
			require.Nil(t, content)
		})
		t.Run("Other error", func(t *testing.T) {
			provider, err := localcas.New(&ariesmockstorage.Provider{
				OpenStoreReturn: &ariesmockstorage.Store{
					ErrGet: errors.New("get error"),
				},
			})
			require.NoError(t, err)

			content, err := provider.Read("AVUSIO1wArQ56ayEXyI1fYIrrBREcw-9tgFtPslDIpe57J9z")
			require.EqualError(t, err, "failed to get content from the underlying storage provider: get error")
			require.Nil(t, content)
		})
	})
	t.Run("Invalid CID version", func(t *testing.T) {
		provider, err := localcas.New(ariesmemstorage.NewProvider(), extendedcasclient.WithCIDVersion(2))
		require.NoError(t, err)

		address, err := provider.Write([]byte("content"))
		require.EqualError(t, err, "2 is not a supported CID version. It must be either 0 or 1")
		require.Equal(t, "", address)
	})
}

func TestEnsureLocalCASAndIPFSProduceSameCIDs(t *testing.T) {
	pool, ipfsResource := startIPFSDockerContainer(t)

	defer func() {
		require.NoError(t, pool.Purge(ipfsResource), "failed to purge IPFS resource")
	}()

	t.Run("v1", func(t *testing.T) {
		ensureCIDsAreEqualBetweenLocalCASAndIPFS(t)
	})
	t.Run("v0", func(t *testing.T) {
		ensureCIDsAreEqualBetweenLocalCASAndIPFS(t, extendedcasclient.WithCIDVersion(0))
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

func ensureCIDsAreEqualBetweenLocalCASAndIPFS(t *testing.T, opts ...extendedcasclient.CIDFormatOption) {
	t.Helper()

	smallSimpleData := []byte("content")

	sampleAnchorCredentialBytes := []byte(sampleAnchorCredential)

	cidFromIPFS := addDataToIPFS(t, smallSimpleData, opts...)
	cidFromLocalCAS := addDataToLocalCAS(t, smallSimpleData, opts...)

	require.Equal(t, cidFromIPFS, cidFromLocalCAS)

	cidFromIPFS = addDataToIPFS(t, sampleAnchorCredentialBytes, opts...)
	cidFromLocalCAS = addDataToLocalCAS(t, sampleAnchorCredentialBytes, opts...)

	require.Equal(t, cidFromIPFS, cidFromLocalCAS)
}

func addDataToIPFS(t *testing.T, data []byte, opts ...extendedcasclient.CIDFormatOption) string {
	t.Helper()

	shell := ipfsshell.NewShell("localhost:5001")

	shell.SetTimeout(2 * time.Second)

	// IPFS will need some time to start up, hence the need for retries.
	var cid string

	options := extendedcasclient.CIDFormatOptions{CIDVersion: 1}

	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}

	var v1AddOpt []ipfsshell.AddOpts

	if options.CIDVersion == 1 {
		v1AddOpt = []ipfsshell.AddOpts{ipfsshell.CidVersion(1)}
	}

	err := backoff.Retry(func() error {
		var err error
		cid, err = shell.Add(bytes.NewReader(data), v1AddOpt...)

		return err
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond*500), 10))
	require.NoError(t, err)

	return cid
}

func addDataToLocalCAS(t *testing.T, data []byte, opts ...extendedcasclient.CIDFormatOption) string {
	t.Helper()

	cas, err := localcas.New(ariesmemstorage.NewProvider(), opts...)
	require.NoError(t, err)

	cid, err := cas.Write(data)
	require.NoError(t, err)

	return cid
}
