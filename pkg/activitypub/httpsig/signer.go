/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"crypto"
	"fmt"
	"net/http"
	"time"

	"github.com/go-fed/httpsig"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("activitypub_httpsig")

const (
	dateHeader        = "Date"
	defaultExpiration = 60 * time.Second
)

// DefaultGetSignerConfig returns the default configuration for signing HTTP GET requests.
func DefaultGetSignerConfig() SignerConfig {
	return SignerConfig{
		Algorithms: []httpsig.Algorithm{"ed25519", "rsa-sha256", "rsa-sha512"},
		Headers:    []string{"(request-target)", "Date"},
	}
}

// DefaultPostSignerConfig returns the default configuration for signing HTTP POST requests.
func DefaultPostSignerConfig() SignerConfig {
	return SignerConfig{
		Algorithms:      []httpsig.Algorithm{"ed25519", "rsa-sha256", "rsa-sha512"},
		DigestAlgorithm: "SHA-256",
		Headers:         []string{"(request-target)", "Date", "Digest"},
	}
}

// SignerConfig contains the confoguration for signing HTTP requests.
type SignerConfig struct {
	Algorithms      []httpsig.Algorithm
	DigestAlgorithm httpsig.DigestAlgorithm
	Headers         []string
	Expiration      time.Duration
}

// Signer signs HTTP requests.
type Signer struct {
	SignerConfig
}

// NewSigner returns a new signer.
func NewSigner(cfg SignerConfig) *Signer {
	s := &Signer{
		SignerConfig: cfg,
	}

	if s.Expiration == 0 {
		s.Expiration = defaultExpiration
	}

	return s
}

// SignRequest signs an HTTP request.
func (s *Signer) SignRequest(pKey crypto.PrivateKey, pubKeyID string, req *http.Request, body []byte) error {
	logger.Debugf("Signing request for %s. Public key ID [%s]", req.RequestURI, pubKeyID)

	signer, _, err := httpsig.NewSigner(s.Algorithms, s.DigestAlgorithm, s.Headers,
		httpsig.Signature, int64(s.Expiration.Seconds()))
	if err != nil {
		return fmt.Errorf("new signer: %w", err)
	}

	req.Header.Add(dateHeader, date())

	err = signer.SignRequest(pKey, pubKeyID, req, body)
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	return nil
}

func date() string {
	return fmt.Sprintf("%s GMT", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05"))
}
