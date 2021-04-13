/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/vct/pkg/client/vct"

	"github.com/trustbloc/orb/pkg/vcsigner"
)

const (
	ctxSecurity = "https://w3id.org/security/v1"
	ctxJWS      = "https://w3id.org/jws/v1"
)

type signer interface {
	Sign(vc *verifiable.Credential, opts ...vcsigner.Opt) (*verifiable.Credential, error)
}

// HTTPClient represents HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client represents VCT client.
type Client struct {
	signer   signer
	endpoint string
	vct      *vct.Client
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
func New(endpoint string, signer signer, opts ...ClientOpt) *Client {
	op := &clientOptions{http: &http.Client{
		Timeout: time.Minute,
	}}

	for _, fn := range opts {
		fn(op)
	}

	return &Client{
		signer:   signer,
		endpoint: endpoint,
		vct:      vct.New(endpoint, vct.WithHTTPClient(op.http)),
	}
}

// Witness credentials.
func (c *Client) Witness(anchorCred []byte) ([]byte, error) {
	resp, err := c.vct.AddVC(context.Background(), anchorCred)
	if err != nil {
		return nil, err
	}

	vc, err := verifiable.ParseCredential(anchorCred,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}

	// adds linked data proof
	vc, err = c.signer.Sign(vc,
		// sets created time from the VCT.
		vcsigner.WithCreated(time.Unix(0, int64(resp.Timestamp)*int64(time.Millisecond))),
		vcsigner.WithSignatureRepresentation(verifiable.SignatureJWS),
		vcsigner.WithDomain(c.endpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("add proof to credential: %w", err)
	}

	// TODO: public key probably needs to be discovered by using a web finger.
	pubKey, err := c.vct.GetPublicKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// gets the latest proof
	proof := vc.Proofs[len(vc.Proofs)-1]

	createdAt, ok := proof["created"].(string)
	if !ok {
		return nil, errors.New("created time is not a string")
	}

	timestampTime, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parse time: %w", err)
	}

	timestamp := uint64(timestampTime.UnixNano()) / uint64(time.Millisecond)
	// verifies the signature by given timestamp from the proof and original credentials.
	err = vct.VerifyVCTimestampSignatureFromBytes(resp.Signature, pubKey, timestamp, anchorCred)
	if err != nil {
		return nil, fmt.Errorf("verify VC timestamp signature: %w", err)
	}

	return json.Marshal(Proof{
		Context: []string{ctxSecurity, ctxJWS},
		Proof:   proof,
	})
}

// Proof represents response.
type Proof struct {
	Context []string         `json:"@context"`
	Proof   verifiable.Proof `json:"proof"`
}
