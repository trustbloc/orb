/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package compression

import (
	"fmt"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
)

const (
	noCompression               = "None"
	defaultCompressionAlgorithm = "GZIP"
)

var logger = log.New("compression")

// New returns new instance of compression provider.
func New(opts ...Option) *Provider {
	cp := compression.New(compression.WithDefaultAlgorithms())

	anchorEventStore := &Provider{
		coreCompressionProvider: cp,
		compressionAlgorithm:    defaultCompressionAlgorithm,
		decompressionAlgorithms: []string{defaultCompressionAlgorithm},
	}

	// apply options
	for _, opt := range opts {
		opt(anchorEventStore)
	}

	return anchorEventStore
}

// compressionProvider defines an interface for handling different types of compression.
type compressionProvider interface {
	Compress(alg string, data []byte) ([]byte, error)
	Decompress(alg string, data []byte) ([]byte, error)
}

// Provider implements compression/decompression provider.
type Provider struct {
	coreCompressionProvider compressionProvider
	compressionAlgorithm    string
	decompressionAlgorithms []string
}

// Option is an option for compression provider.
type Option func(opts *Provider)

// WithCompressionAlgorithm sets optional current compression algorithm(default is GZIP).
func WithCompressionAlgorithm(alg string) Option {
	return func(opts *Provider) {
		opts.compressionAlgorithm = alg
	}
}

// WithDecompressionAlgorithms sets optional all supported decompression algorithms(default is GZIP).
func WithDecompressionAlgorithms(algorithms []string) Option {
	return func(opts *Provider) {
		opts.decompressionAlgorithms = algorithms
	}
}

// WithCompressionProvider sets optional compression/decompression provider.
func WithCompressionProvider(cp compressionProvider) Option {
	return func(opts *Provider) {
		opts.coreCompressionProvider = cp
	}
}

// Compress will compress value using default configured compression algorithm and return
// compressed content type and compressed bytes.
func (p *Provider) Compress(value []byte) (string, []byte, error) {
	if p.compressionAlgorithm == noCompression {
		return noCompression, value, nil
	}

	compressed, err := p.coreCompressionProvider.Compress(p.compressionAlgorithm, value)
	if err != nil {
		return "", nil, err
	}

	// TODO: convert from compression algorithm to compression content type - for now return compression algorithm
	return p.compressionAlgorithm, compressed, nil
}

// Decompress will decompress value based on hint in id (if provided) otherwise it will try to decompress value
// based on system configuration.
func (p *Provider) Decompress(id string, compressed []byte) ([]byte, error) {
	// TODO: Parse id to see if there is compression hint provided

	for _, alg := range p.decompressionAlgorithms {
		if alg == noCompression {
			return compressed, nil
		}

		value, err := p.coreCompressionProvider.Decompress(alg, compressed)
		if err == nil {
			return value, nil
		}

		logger.Debugf("unable to decompress id[%s] with algorithm[%s]: %s", id, alg, err.Error())
	}

	return nil, fmt.Errorf("unable to decompress id[%s] with supported algorithms%s",
		id, p.decompressionAlgorithms)
}
