/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashlink

import (
	"encoding/base64"
	"fmt"
	"strings"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/multiformats/go-multihash"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
)

const (
	sha2_256 = 18
	linksKey = 0x0f

	hl        = "hl"
	separator = ":"

	maxHLParts = 3
	minHLParts = 2

	// HLPrefix is hash link prefix.
	HLPrefix = hl + separator
)

// Encoder defines encoding function.
type Encoder func(content []byte) string

// Decoder defines decoding function.
type Decoder func(encodedContent string) ([]byte, error)

// New creates HashLink.
func New(opts ...Option) *HashLink {
	// default encoder/decoder is base64 URL encoder/decoder
	hl := &HashLink{
		multihashCode: sha2_256,
		encoder: func(data []byte) string {
			return "u" + base64.RawURLEncoding.EncodeToString(data)
		},
		decoder: func(enc string) ([]byte, error) {
			return base64.RawURLEncoding.DecodeString(enc[1:])
		},
	}

	for _, opt := range opts {
		opt(hl)
	}

	return hl
}

// Option is a hashlink instance option.
type Option func(opts *HashLink)

// HashLink implements hashlink related functionality.
type HashLink struct {
	encoder       Encoder
	decoder       Decoder
	multihashCode uint
}

// CreateHashLink will create hashlink for the supplied content and links.
func (hl *HashLink) CreateHashLink(content []byte, links []string) (string, error) {
	hashLink, err := hl.CreateResourceHash(content)
	if err != nil {
		return "", fmt.Errorf("failed to create resource hash from content[%s]: %w", string(content), err)
	}

	// hash link without metadata
	hashLink = HLPrefix + hashLink

	if len(links) > 0 {
		metadata, err := hl.CreateMetadataFromLinks(links)
		if err != nil {
			return "", fmt.Errorf("failed to create hashlink metadata for links[%+v]: %w", links, err)
		}

		// add metadata to hashlink
		hashLink = hashLink + separator + metadata
	}

	return hashLink, nil
}

// ParseHashLink will parse hash link into resource hash and metadata.
func (hl *HashLink) ParseHashLink(hashLink string) (*Info, error) {
	if !strings.HasPrefix(hashLink, HLPrefix) {
		return nil, fmt.Errorf("hashlink '%s' must start with '%s' prefix", hashLink, HLPrefix)
	}

	parts := strings.Split(hashLink, separator)
	if len(parts) > maxHLParts {
		return nil, fmt.Errorf("hashlink[%s] has more than %d parts", hashLink, maxHLParts)
	}

	// resource hash
	rh := parts[1]

	err := hl.isValidMultihash(rh)
	if err != nil {
		return nil, fmt.Errorf("resource hash[%s] for hashlink[%s] is not a valid multihash: %w", rh, hashLink, err)
	}

	info := &Info{ResourceHash: rh}

	if len(parts) > minHLParts {
		links, err := hl.GetLinksFromMetadata(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to get links from metadata: %w", err)
		}

		info.Links = links
	}

	return info, nil
}

// Info contains hashlink information: resource hash and links.
type Info struct {
	ResourceHash string
	Links        []string
}

// CreateResourceHash will create resource hash for the supplied content.
func (hl *HashLink) CreateResourceHash(content []byte) (string, error) {
	mh, err := hashing.ComputeMultihash(hl.multihashCode, content)
	if err != nil {
		return "", fmt.Errorf("failed to compute multihash for code[%d]: %w", hl.multihashCode, err)
	}

	return hl.encoder(mh), nil
}

// CreateMetadataFromLinks will create metadata for the supplied links.
func (hl *HashLink) CreateMetadataFromLinks(links []string) (string, error) {
	if len(links) == 0 {
		return "", fmt.Errorf("links not provided")
	}

	// generate the encoded metadata
	metadata := make(map[int]interface{})
	metadata[linksKey] = links

	bytes, err := cbor.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to cbor.marshal links[%+v]: %w", links, err)
	}

	return hl.encoder(bytes), nil
}

// GetLinksFromMetadata will create links from metadata.
func (hl *HashLink) GetLinksFromMetadata(enc string) ([]string, error) {
	metadataBytes, err := hl.decoder(enc)
	if err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	var metadata map[int]interface{}

	err = cbor.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to cbor.unmarshal metadata: %w", err)
	}

	linksObj, ok := metadata[linksKey]
	if !ok {
		return nil, fmt.Errorf("failed to get links from metadata: missing key")
	}

	links, err := toStringArray(linksObj)
	if err != nil {
		return nil, fmt.Errorf("failed to convert links from metadata to string array: %w", err)
	}

	return links, nil
}

// WithEncoder option is for specifying custom encoder.
func WithEncoder(enc Encoder) Option {
	return func(opts *HashLink) {
		opts.encoder = enc
	}
}

// WithDecoder option is for specifying custom decoder.
func WithDecoder(dec Decoder) Option {
	return func(opts *HashLink) {
		opts.decoder = dec
	}
}

// WithMultihashCode option is for specifying custom multihash code.
func WithMultihashCode(mhCode uint) Option {
	return func(opts *HashLink) {
		opts.multihashCode = mhCode
	}
}

// GetHashLink will create hashlink from resource hash and metadata.
func GetHashLink(resource, metadata string) string {
	return fmt.Sprintf("%s:%s:%s", hl, resource, metadata)
}

// GetHashLinkFromResourceHash will create hashlink from resource hash.
func GetHashLinkFromResourceHash(resource string) string {
	return fmt.Sprintf("%s:%s", hl, resource)
}

// GetResourceHashFromHashLink will return resource hash.
func GetResourceHashFromHashLink(hashLink string) (string, error) {
	if !strings.HasPrefix(hashLink, HLPrefix) {
		return "", fmt.Errorf("hashlink[%s] must start with '%s' prefix", hashLink, HLPrefix)
	}

	parts := strings.Split(hashLink, separator)

	return parts[1], nil
}

// StringArray is utility function to return string array from interface.
func toStringArray(obj interface{}) ([]string, error) {
	if obj == nil {
		return nil, fmt.Errorf("obj is nil")
	}

	entries, ok := obj.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expecting an array, got '%T'", obj)
	}

	var result []string

	for _, entry := range entries {
		strEntry, err := stringEntry(entry)
		if err != nil {
			return nil, err
		}

		result = append(result, strEntry)
	}

	return result, nil
}

func stringEntry(entry interface{}) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("entry is nil")
	}

	entryStr, ok := entry.(string)
	if !ok {
		return "", fmt.Errorf("expecting string, got '%T'", entry)
	}

	return entryStr, nil
}

func (hl *HashLink) isValidMultihash(encodedMultihash string) error {
	multihashBytes, err := hl.decoder(encodedMultihash)
	if err != nil {
		return fmt.Errorf("failed to decode encoded multihash: %w", err)
	}

	mh, err := multihash.Decode(multihashBytes)
	if err != nil {
		return fmt.Errorf("failed to decode multihash: %w", err)
	}

	if mh.Code != uint64(hl.multihashCode) {
		return fmt.Errorf("resource multihash code[%d] is not supported code[%d]", mh.Code, hl.multihashCode)
	}

	return nil
}
