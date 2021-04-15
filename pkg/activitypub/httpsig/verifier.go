/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-fed/httpsig"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// DefaultVerifierConfig returns the default configuration for verifying HTTP requests.
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		Algorithms: []httpsig.Algorithm{httpsig.ED25519},
	}
}

// VerifierConfig contains the configuration for verifying HTTP requests.
type VerifierConfig struct {
	Algorithms []httpsig.Algorithm
}

type actorRetriever interface {
	GetActor(actorIRI *url.URL) (*vocab.ActorType, error)
	GetPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error)
}

// Verifier verifies signatures of HTTP requests.
type Verifier struct {
	VerifierConfig
	retriever actorRetriever
}

// NewVerifier returns a new HTTP signature verifier.
func NewVerifier(cfg VerifierConfig, retriever actorRetriever) *Verifier {
	return &Verifier{
		VerifierConfig: cfg,
		retriever:      retriever,
	}
}

// VerifyRequest verifies the HTTP signature on the request and returns the IRI of the actor
// for the key ID in the request header. The actor IRI may then be used to verify that it
// matches the actor in a posted activity.
func (v *Verifier) VerifyRequest(req *http.Request) (*url.URL, error) {
	logger.Debugf("Verifying HTTP %s request from %s with headers %s", req.Method, req.URL, req.Header)

	verifier, err := httpsig.NewVerifier(req)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	pubKey, err := v.loadAndVerifyPublicKey(verifier.KeyId())
	if err != nil {
		return nil, fmt.Errorf("unable to verify public key for ID [%s]: %w", verifier.KeyId(), err)
	}

	block, rest := pem.Decode([]byte(pubKey.PublicKeyPem))
	if block == nil {
		logger.Warnf("invalid public key: nil block. Rest: %s", rest)

		return nil, fmt.Errorf("invalid public key for ID [%s]: nil block", verifier.KeyId())
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key for ID [%s]: %w", verifier.KeyId(), err)
	}

	// TODO: Resolve the algorithm from the keyId according to
	// https://tools.ietf.org/html/draft-cavage-http-signatures-12#section-2.5.
	// Use the first algorithm for now.
	algo := v.Algorithms[0]

	logger.Debugf("Verifying HTTP signature with public key [%s]", verifier.KeyId())

	return pubKey.Owner.URL(), verifier.Verify(pk, algo)
}

func (v *Verifier) loadAndVerifyPublicKey(keyID string) (*vocab.PublicKeyType, error) {
	keyIRI, err := url.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("parse key IRI [%s]: %w", keyID, err)
	}

	pubKey, err := v.retriever.GetPublicKey(keyIRI)
	if err != nil {
		return nil, fmt.Errorf("retrieve public key for ID [%s]: %w", keyID, err)
	}

	// Ensure that the public key ID matches the key ID of the specified owner. Otherwise it could
	// be an attempt to impersonate an actor.
	actor, err := v.retriever.GetActor(pubKey.Owner.URL())
	if err != nil {
		return nil, fmt.Errorf("retrieve actor [%s]: %w", pubKey.Owner, err)
	}

	if actor.PublicKey() == nil {
		return nil, fmt.Errorf("unable to verify owner [%s] of public key [%s] since owner has nil key",
			actor.ID(), keyID)
	}

	if actor.PublicKey().ID.String() != pubKey.ID.String() {
		return nil, fmt.Errorf("public key of actor does not match the public key ID in the request: [%s]",
			actor.PublicKey().ID)
	}

	return pubKey, nil
}
