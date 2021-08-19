/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"errors"
	"fmt"
	"time"

	"github.com/bluele/gcache"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
)

var logger = log.New("cas-store")

const (
	defaultCacheSize = 1000
	casType          = "local"
)

type metricsProvider interface {
	CASIncrementCacheHitCount()
	CASReadTime(casType string, value time.Duration)
}

// CAS represents a content-addressable storage provider.
type CAS struct {
	cas        ariesstorage.Store
	ipfsClient *ipfs.Client
	opts       []extendedcasclient.CIDFormatOption
	cache      gcache.Cache
	metrics    metricsProvider
	casLink    string
	hl         *hashlink.HashLink
}

// New returns a new CAS that uses the passed in provider as a backing store for local CAS storage.
// ipfsClient is optional, but if provided (not nil), then writes will go to IPFS in addition to the passed in provider.
// Reads are always done on only the passed in provider.
// If no CID version is specified, then v1 will be used by default.
func New(provider ariesstorage.Provider, casLink string, ipfsClient *ipfs.Client,
	metrics metricsProvider, cacheSize int, opts ...extendedcasclient.CIDFormatOption) (*CAS, error) {
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
		hl:         hashlink.New(),
		casLink:    casLink,
	}

	c.cache = gcache.New(cacheSize).ARC().
		LoaderFunc(func(key interface{}) (interface{}, error) {
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
	if len(content) == 0 {
		return "", errors.New("empty content")
	}

	resourceHash, err := p.hl.CreateResourceHash(content)
	if err != nil {
		return "", fmt.Errorf("failed to create resource hash from content: %w", err)
	}

	logger.Debugf("Writing to CAS store [%s]: %s", resourceHash, content)

	err = p.cas.Put(resourceHash, content)
	if err != nil {
		return "", orberrors.NewTransient(fmt.Errorf("failed to put content into underlying storage provider: %w", err))
	}

	// add cas link
	links := []string{p.casLink + "/" + resourceHash}

	if p.ipfsClient != nil {
		cid, writeErr := p.ipfsClient.WriteWithCIDFormat(content, opts...)
		if writeErr != nil {
			return "", orberrors.NewTransient(fmt.Errorf("failed to put content into IPFS (but it was "+
				"successfully stored in the local storage provider): %w", writeErr))
		}

		// add ipfs link
		links = append(links, "ipfs://"+cid)
	}

	if err = p.cache.Set(resourceHash, content); err != nil {
		// This shouldn't be possible.
		logger.Warnf("Error caching content for resource hash[%s]: %s", resourceHash, err)
	} else {
		logger.Debugf("Cached content for resource hash [%s]", resourceHash)
	}

	metadata, err := p.hl.CreateMetadataFromLinks(links)
	if err != nil {
		return "", fmt.Errorf("failed to create resource hash from content: %w", err)
	}

	return hashlink.GetHashLink(resourceHash, metadata), nil
}

// GetPrimaryWriterType returns primary writer type.
func (p *CAS) GetPrimaryWriterType() string {
	return "local"
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
	startTime := time.Now()

	defer func() {
		p.metrics.CASReadTime(casType, time.Since(startTime))
	}()

	content, err := p.cas.Get(address)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, orberrors.NewTransient(fmt.Errorf("failed to get content from the local CAS provider: %w", err))
	}

	return content, nil
}
