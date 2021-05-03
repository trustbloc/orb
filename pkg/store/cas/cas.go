/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"errors"
	"fmt"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// ErrContentNotFound is used to indicate that content as a given address could not be found.
var ErrContentNotFound = errors.New("content not found")

// CAS represents a content-addressable storage provider.
type CAS struct {
	cas ariesstorage.Store
}

// New returns a new CAS that uses the passed in provider as a backing store.
func New(provider ariesstorage.Provider) (*CAS, error) {
	cas, err := provider.OpenStore("cas_store")
	if err != nil {
		return nil, fmt.Errorf("failed to open store in underlying storage provider: %w", err)
	}

	return &CAS{cas: cas}, nil
}

// Write writes the given content to the underlying storage provider.
// Returns the address of the content.
func (p *CAS) Write(content []byte) (string, error) {
	// TODO #318 figure out why the CIDs produced here differ from the ones that IPFS generates.
	prefix := cid.Prefix{
		Version:  0,
		MhType:   mh.SHA2_256,
		MhLength: -1, // default length
	}

	contentID, err := prefix.Sum(content)
	if err != nil {
		return "", fmt.Errorf("failed to generate CID: %w", err)
	}

	err = p.cas.Put(contentID.String(), content)
	if err != nil {
		return "", fmt.Errorf("failed to put content into underlying storage provider: %w", err)
	}

	return contentID.String(), nil
}

// Read reads the content of the given address from the underlying storage provider.
// Returns the content at the given address.
func (p *CAS) Read(address string) ([]byte, error) {
	content, err := p.cas.Get(address)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return nil, ErrContentNotFound
		}

		return nil, fmt.Errorf("failed to get content from the underlying storage provider: %w", err)
	}

	return content, nil
}
