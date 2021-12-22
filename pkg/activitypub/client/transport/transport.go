/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	apclientmocks "github.com/trustbloc/orb/pkg/activitypub/client/mocks"
)

var logger = log.New("activitypub_client")

const (
	// AcceptHeader specifies the content type that the client is expecting.
	AcceptHeader = "Accept"

	// LDPlusJSONContentType specifies the linked data plus JSON content type.
	LDPlusJSONContentType = `application/ld+json`

	// ActivityStreamsContentType is the content type used for activity streams messages.
	ActivityStreamsContentType = `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`
)

// Signer signs an HTTP request and adds the signature to the header of the request.
type Signer interface {
	SignRequest(pubKeyID string, req *http.Request) error
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type authTokenManager interface {
	IsAuthRequired(endpoint, method string) (bool, error)
}

// Transport implements a client-side transport that Gets and Posts requests using HTTP signatures.
type Transport struct {
	client      httpClient
	getSigner   Signer
	postSigner  Signer
	publicKeyID *url.URL
	tokenMgr    authTokenManager
}

// New returns a new transport.
func New(client httpClient, publicKeyID *url.URL, getSigner, postSigner Signer, tm authTokenManager) *Transport {
	return &Transport{
		client:      client,
		publicKeyID: publicKeyID,
		getSigner:   getSigner,
		postSigner:  postSigner,
		tokenMgr:    tm,
	}
}

// Request contains the destination URL and headers.
type Request struct {
	URL    *url.URL
	Header http.Header
}

type options struct {
	header http.Header
}

// Option defines a transport option.
type Option func(options *options)

// WithHeader specifies a header in the HTTP request.
func WithHeader(name string, values ...string) Option {
	return func(options *options) {
		options.header[name] = values
	}
}

// NewRequest returns a new request.
func NewRequest(toURL *url.URL, opts ...Option) *Request {
	options := &options{
		header: make(http.Header),
	}

	for _, opt := range opts {
		opt(options)
	}

	return &Request{
		URL:    toURL,
		Header: options.header,
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
		tokenMgr:    &apclientmocks.AuthTokenMgr{},
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

	for k, v := range r.Header {
		req.Header[k] = v
	}

	authRequired, err := t.tokenMgr.IsAuthRequired(r.URL.Path, http.MethodPost)
	if err != nil {
		return nil, fmt.Errorf("is authorization required: %w", err)
	}

	if authRequired {
		err = t.postSigner.SignRequest(t.publicKeyID.String(), req)
		if err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}

		logger.Debugf("Signed HTTP POST to %s. Headers: %s", r.URL, req.Header)
	} else {
		logger.Debugf("HTTP signature is not required for HTTP POST to %s", r.URL)
	}

	return t.client.Do(req)
}

// Get sends an HTTP GET. The HTTP request is first signed and the signature is added to the request header.
func (t *Transport) Get(ctx context.Context, r *Request) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("get from %s: %w", r.URL, err)
	}

	for k, v := range r.Header {
		req.Header[k] = v
	}

	authRequired, err := t.tokenMgr.IsAuthRequired(r.URL.Path, http.MethodGet)
	if err != nil {
		return nil, fmt.Errorf("is authorization required: %w", err)
	}

	if authRequired {
		err = t.getSigner.SignRequest(t.publicKeyID.String(), req)
		if err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}

		logger.Debugf("Signed HTTP GET to %s. Headers: %s", r.URL, req.Header)
	} else {
		logger.Debugf("HTTP signature is not required for HTTP GET to %s", r.URL)
	}

	return t.client.Do(req)
}

// NoOpSigner is a signer that does nothing. This signer should only be used by tests.
type NoOpSigner struct{}

// DefaultSigner returns a default, no-op signer. This signer should only be used by tests.
func DefaultSigner() *NoOpSigner {
	return &NoOpSigner{}
}

// SignRequest does nothing.
func (s *NoOpSigner) SignRequest(pubKeyID string, req *http.Request) error {
	return nil
}
