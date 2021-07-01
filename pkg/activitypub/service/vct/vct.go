/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vct

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/vcsigner"
)

const (
	ctxSecurity = "https://w3id.org/security/v1"
	ctxJWS      = "https://w3id.org/security/jws/v1"
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
	signer         signer
	documentLoader ld.DocumentLoader
	vct            *vct.Client
}

// ClientOpt represents client option func.
type ClientOpt func(*clientOptions)

type clientOptions struct {
	http           HTTPClient
	documentLoader ld.DocumentLoader
}

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(client HTTPClient) ClientOpt {
	return func(o *clientOptions) {
		o.http = client
	}
}

// WithDocumentLoader allows providing document loader.
func WithDocumentLoader(loader ld.DocumentLoader) ClientOpt {
	return func(o *clientOptions) {
		o.documentLoader = loader
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

	var vctClient *vct.Client

	// TODO: endpoint should be resolved using webfinger.
	if strings.TrimSpace(endpoint) != "" {
		vctClient = vct.New(endpoint, vct.WithHTTPClient(op.http))
	}

	return &Client{
		signer:         signer,
		documentLoader: op.documentLoader,
		vct:            vctClient,
	}
}

func (c *Client) addProof(anchorCred []byte, timestamp int64) (*verifiable.Credential, error) {
	vc, err := verifiable.ParseCredential(anchorCred,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(c.documentLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}

	// adds linked data proof
	vc, err = c.signer.Sign(vc,
		// sets created time from the VCT.
		vcsigner.WithCreated(time.Unix(0, timestamp)),
		vcsigner.WithSignatureRepresentation(verifiable.SignatureJWS),
	)
	if err != nil {
		return nil, fmt.Errorf("add proof to credential: %w", err)
	}

	return vc, nil
}

// Witness credentials.
func (c *Client) Witness(anchorCred []byte) ([]byte, error) { // nolint: funlen,gocyclo,cyclop
	if c.vct == nil {
		vc, err := c.addProof(anchorCred, time.Now().UnixNano())
		if err != nil {
			return nil, fmt.Errorf("add proof: %w", err)
		}

		return json.Marshal(Proof{
			Context: []string{ctxSecurity, ctxJWS},
			Proof:   vc.Proofs[len(vc.Proofs)-1], // gets the latest proof
		})
	}

	resp, err := c.vct.AddVC(context.Background(), anchorCred)
	if err != nil {
		return nil, err
	}

	vc, err := c.addProof(anchorCred, int64(resp.Timestamp)*int64(time.Millisecond))
	if err != nil {
		return nil, fmt.Errorf("add proof: %w", err)
	}

	webResp, err := c.vct.Webfinger(context.Background())
	if err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}

	pubKeyRaw, ok := webResp.Properties[command.PublicKeyType]
	if !ok {
		return nil, fmt.Errorf("no public key")
	}

	pubKeyStr, ok := pubKeyRaw.(string)
	if !ok {
		return nil, fmt.Errorf("public key is not a string")
	}

	pubKey, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
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
	err = vct.VerifyVCTimestampSignature(resp.Signature, pubKey, timestamp, vc)
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
