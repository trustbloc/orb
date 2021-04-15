/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("activitypub_client")

// Signer signs an HTTP request and adds the signature to the header of the request.
type Signer interface {
	SignRequest(pKey crypto.PrivateKey, pubKeyID string, r *http.Request, body []byte) error
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Transport implements a client-side transport that Gets and Posts requests using HTTP signatures.
type Transport struct {
	client      httpClient
	getSigner   Signer
	postSigner  Signer
	privateKey  crypto.PrivateKey
	publicKeyID *url.URL
}

// New returns a new transport.
func New(client httpClient, privateKey crypto.PrivateKey, publicKeyID *url.URL,
	getSigner, postSigner Signer) *Transport {
	return &Transport{
		client:      client,
		privateKey:  privateKey,
		publicKeyID: publicKeyID,
		getSigner:   getSigner,
		postSigner:  postSigner,
	}
}

// Request contains the destination URL and headers.
type Request struct {
	URL    *url.URL
	Header http.Header
}

// NewRequest returns a new request.
func NewRequest(toURL *url.URL) *Request {
	return &Request{
		URL:    toURL,
		Header: make(http.Header),
	}
}

// Default returns a default transport that uses the default HTTP client and no HTTP signatures.
// This transport should only be used by tests.
func Default() *Transport {
	return &Transport{
		client:      http.DefaultClient,
		publicKeyID: &url.URL{},
		getSigner:   &NoOpSigner{},
		postSigner:  &NoOpSigner{},
	}
}

// Post posts an HTTP request. The HTTP request is first signed and the signature is added to the request header.
func (t *Transport) Post(ctx context.Context, r *Request, payload []byte) (*http.Response, error) {
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewBuffer(payload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("new request to %s: %w", r.URL, err)
	}

	req.Header = r.Header

	err = t.postSigner.SignRequest(t.privateKey, t.publicKeyID.String(), req, payload)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	logger.Debugf("Signed HTTP POST to %s. Headers: %s", r.URL, req.Header)

	return t.client.Do(req)
}

// Get sends an HTTP GET. The HTTP request is first signed and the signature is added to the request header.
func (t *Transport) Get(ctx context.Context, r *Request) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("get from %s: %w", r.URL, err)
	}

	req.Header = r.Header

	logger.Debugf("Signed HTTP GET to %s. Headers: %s", r.URL, req.Header)

	err = t.getSigner.SignRequest(t.privateKey, t.publicKeyID.String(), req, nil)
	if err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	return t.client.Do(req)
}

// NoOpSigner is a signer that does nothing. This signer should only be used by tests.
type NoOpSigner struct {
}

// DefaultSigner returns a default, no-op signer. This signer should only be used by tests.
func DefaultSigner() *NoOpSigner {
	return &NoOpSigner{}
}

// SignRequest does nothing.
func (s *NoOpSigner) SignRequest(crypto.PrivateKey, string, *http.Request, []byte) error {
	return nil
}
