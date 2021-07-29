/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"errors"
	"fmt"

	"github.com/bluele/gcache"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	gocid "github.com/ipfs/go-cid"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-unixfs"
	mh "github.com/multiformats/go-multihash"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("cas-store")

const defaultCacheSize = 1000

type metricsProvider interface {
	CASIncrementCacheHitCount()
	CASIncrementCacheMissCount()
}

// CAS represents a content-addressable storage provider.
type CAS struct {
	cas        ariesstorage.Store
	ipfsClient *ipfs.Client
	opts       []extendedcasclient.CIDFormatOption
	cache      gcache.Cache
	metrics    metricsProvider
}

// New returns a new CAS that uses the passed in provider as a backing store for local CAS storage.
// ipfsClient is optional, but if provided (not nil), then writes will go to IPFS in addition to the passed in provider.
// Reads are always done on only the passed in provider.
// If no CID version is specified, then v1 will be used by default.
func New(provider ariesstorage.Provider, ipfsClient *ipfs.Client, metrics metricsProvider, cacheSize int,
	opts ...extendedcasclient.CIDFormatOption) (*CAS, error) {
	cas, err := provider.OpenStore("cas_store")
	if err != nil {
		return nil, fmt.Errorf("failed to open store in underlying storage provider: %w", err)
	}

	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}

	c := &CAS{
		cas:        cas,
		ipfsClient: ipfsClient,
		opts:       opts,
		metrics:    metrics,
	}

	c.cache = gcache.New(cacheSize).ARC().
		LoaderFunc(func(key interface{}) (interface{}, error) {
			c.metrics.CASIncrementCacheMissCount()

			cid, err := c.get(key.(string))
			if err != nil {
				return nil, err
			}

			logger.Debugf("Cached content for CID [%s]", cid)

			return cid, nil
		},
		).Build()

	return c, nil
}

// Write writes the given content to the underlying CAS provider (and IPFS if configured) using this CAS'
// default CID version.
// Returns the address of the content.
func (p *CAS) Write(content []byte) (string, error) {
	return p.WriteWithCIDFormat(content, p.opts...)
}

// WriteWithCIDFormat writes the given content to the underlying local CAS provider (and IPFS if configured) using the
// CID format specified by opts.
// Returns the address of the content.
// TODO (#418): Support creating IPFS-compatible CIDs when content is > 256KB.
// TODO (#443): Support v1 CID formats (different multibases and multicodecs) other than just the IPFS default.
func (p *CAS) WriteWithCIDFormat(content []byte, opts ...extendedcasclient.CIDFormatOption) (string, error) {
	options, err := getOptions(opts)
	if err != nil {
		return "", err
	}

	var cid string
	if options.CIDVersion == 0 {
		// The v0 CID produced below is equal to what an IPFS node would produce, assuming that:
		// 1. The IPFS node is running with default settings, and
		// 2. The size of the content passed in here is less than 256KB (the default chunk size).
		// Two levels of wrapping are needed. First, the raw data is wrapped as a protobuf UnixFS file, then that needs
		// to be further wrapped as a protobuf DAG node.
		cid = merkledag.NodeWithData(unixfs.FilePBData(content, uint64(len(content)))).Cid().String()
	} else {
		prefix := gocid.Prefix{
			Version:  1,
			Codec:    gocid.Raw,
			MhType:   mh.SHA2_256,
			MhLength: -1, // default length
		}

		contentID, err := prefix.Sum(content)
		if err != nil {
			return "", fmt.Errorf("failed to generate CID: %w", err)
		}

		cid = contentID.String()
	}

	if err := p.cas.Put(cid, content); err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("failed to put content into underlying storage provider: %w", err))
	}

	if p.ipfsClient != nil {
		if _, err := p.ipfsClient.WriteWithCIDFormat(content, opts...); err != nil {
			return "", orberrors.NewTransient(fmt.Errorf("failed to put content into IPFS (but it was "+
				"successfully stored in the local storage provider): %w", err))
		}
	}

	if err := p.cache.Set(cid, content); err != nil {
		// This shouldn't be possible.
		logger.Warnf("Error caching content for CID [%s]: %s", cid, err)
	} else {
		logger.Debugf("Cached content for CID [%s]", cid)
	}

	return cid, nil
}

// Read reads the content of the given address from the underlying local CAS provider.
// Returns the content at the given address.
func (p *CAS) Read(address string) ([]byte, error) {
	if p.cache.Has(address) {
		p.metrics.CASIncrementCacheHitCount()
	}

	content, err := p.cache.Get(address)
	if err != nil {
		return nil, err
	}

	return content.([]byte), nil
}

func (p *CAS) get(address string) ([]byte, error) {
	content, err := p.cas.Get(address)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, orberrors.NewTransient(fmt.Errorf("failed to get content from the local CAS provider: %w", err))
	}

	return content, nil
}

func getOptions(opts []extendedcasclient.CIDFormatOption) (extendedcasclient.CIDFormatOptions, error) {
	options := extendedcasclient.CIDFormatOptions{CIDVersion: 1}

	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}

	if options.CIDVersion != 0 && options.CIDVersion != 1 {
		return extendedcasclient.CIDFormatOptions{},
			fmt.Errorf("%d is not a supported CID version. It must be either 0 or 1", options.CIDVersion)
	}

	return options, nil
}
