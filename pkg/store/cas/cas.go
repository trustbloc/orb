/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"errors"
	"fmt"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	gocid "github.com/ipfs/go-cid"
	"github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-unixfs"
	mh "github.com/multiformats/go-multihash"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
)

// ErrContentNotFound is used to indicate that content as a given address could not be found.
var ErrContentNotFound = errors.New("content not found")

// CAS represents a content-addressable storage provider.
type CAS struct {
	cas  ariesstorage.Store
	opts []extendedcasclient.CIDFormatOption
}

// New returns a new CAS that uses the passed in provider as a backing store.
// If no CID version is specified, then v1 will be used by default.
func New(provider ariesstorage.Provider, opts ...extendedcasclient.CIDFormatOption) (*CAS, error) {
	cas, err := provider.OpenStore("cas_store")
	if err != nil {
		return nil, fmt.Errorf("failed to open store in underlying storage provider: %w", err)
	}

	return &CAS{cas: cas, opts: opts}, nil
}

// Write writes the given content to the underlying storage provider using this CAS' default CID version.
// Returns the address of the content.
func (p *CAS) Write(content []byte) (string, error) {
	return p.WriteWithCIDFormat(content, p.opts...)
}

// WriteWithCIDFormat writes the given content to the underlying storage provider.
// If useV0CID is true, then the older v0 CID version will be used for calculating the address of the content instead
// of the newer v1 version.
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
		return "", fmt.Errorf("failed to put content into underlying storage provider: %w", err)
	}

	return cid, nil
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
