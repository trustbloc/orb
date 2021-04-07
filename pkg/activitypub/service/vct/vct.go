/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct

import (
	"context"
	"net/http"
	"time"

	"github.com/trustbloc/vct/pkg/client/vct"
)

// HTTPClient represents HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client represents VCT client.
type Client struct {
	vct *vct.Client
}

// ClientOpt represents client option func.
type ClientOpt func(*clientOptions)

type clientOptions struct {
	http HTTPClient
}

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(client HTTPClient) ClientOpt {
	return func(o *clientOptions) {
		o.http = client
	}
}

// New returns the client.
func New(endpoint string, opts ...ClientOpt) *Client {
	op := &clientOptions{http: &http.Client{
		Timeout: time.Minute,
	}}

	for _, fn := range opts {
		fn(op)
	}

	return &Client{
		vct: vct.New(endpoint, vct.WithHTTPClient(op.http)),
	}
}

// Witness credentials.
func (c *Client) Witness(anchorCred []byte) ([]byte, error) {
	resp, err := c.vct.AddVC(context.Background(), anchorCred)
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}
