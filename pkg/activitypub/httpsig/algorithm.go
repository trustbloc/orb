/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	ariesverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	httpsig "github.com/igor-pavlenko/httpsignatures-go"
)

const orbHTTPSigAlgorithm = "https://github.com/trustbloc/orb/httpsig"

// ErrInvalidSignature indicates that the signature is not valid for the given data.
var ErrInvalidSignature = errors.New("invalid HTTP signature")

type keyResolver interface {
	// Resolve returns the public key bytes and the type of public key for the given key ID.
	Resolve(keyID string) (*ariesverifier.PublicKey, error)
}

// SignatureHashAlgorithm is a custom httpsignatures.SignatureHashAlgorithm that uses KMS to sign HTTP requests.
type SignatureHashAlgorithm struct {
	Crypto      crypto.Crypto
	KMS         kms.KeyManager
	keyResolver keyResolver
	keyID       string
}

// NewSignerAlgorithm returns a new SignatureHashAlgorithm which uses KMS to sign HTTP requests.
func NewSignerAlgorithm(c crypto.Crypto, km kms.KeyManager, keyID string) *SignatureHashAlgorithm {
	return &SignatureHashAlgorithm{
		Crypto: c,
		KMS:    km,
		keyID:  keyID,
	}
}

// NewVerifierAlgorithm returns a new SignatureHashAlgorithm which is used to verify the signature
// in the HTTP request header.
func NewVerifierAlgorithm(c crypto.Crypto, km kms.KeyManager, keyResolver keyResolver) *SignatureHashAlgorithm {
	return &SignatureHashAlgorithm{
		Crypto:      c,
		KMS:         km,
		keyResolver: keyResolver,
	}
}

// Algorithm returns this algorithm's name.
func (a *SignatureHashAlgorithm) Algorithm() string {
	return orbHTTPSigAlgorithm
}

// Create signs data with the secret.
func (a *SignatureHashAlgorithm) Create(secret httpsig.Secret, data []byte) ([]byte, error) {
	kh, err := a.KMS.Get(a.keyID)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	logger.Debugf("Got key handle for key ID [%s]. Signing ...", secret.KeyID)

	sig, err := a.Crypto.Sign(data, kh)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}

	logger.Debugf("... successfully signed data with keyID from KMS [%s]", a.keyID)

	return sig, nil
}

// Verify verifies the signature over data with the secret.
func (a *SignatureHashAlgorithm) Verify(secret httpsig.Secret, data, signature []byte) error {
	pubKey, err := a.keyResolver.Resolve(secret.KeyID)
	if err != nil {
		return fmt.Errorf("resolve key %s: %w", secret.KeyID, err)
	}

	logger.Debugf("Got key %+v from keyID [%s]", pubKey, secret.KeyID)

	if !ed25519.Verify(pubKey.Value, data, signature) {
		logger.Infof("Signature verification failed using keyID [%s]", secret.KeyID)

		return ErrInvalidSignature
	}

	logger.Debugf("Successfully verified signature using keyID [%s]", secret.KeyID)

	return nil
}

// KeyResolver resolves the public key for an ActivityPub actor.
type KeyResolver struct {
	pubKeyRetriever actorRetriever
}

// NewKeyResolver returns a new KeyResolver.
func NewKeyResolver(actorRetriever actorRetriever) *KeyResolver {
	return &KeyResolver{pubKeyRetriever: actorRetriever}
}

// Resolve returns the public key for the given key ID.
func (r *KeyResolver) Resolve(keyID string) (*ariesverifier.PublicKey, error) {
	keyIRI, err := url.Parse(keyID)
	if err != nil {
		logger.Errorf("Error parsing public key IRI [%s]: %s", keyID, err)

		return nil, fmt.Errorf("parse key IRI [%s]: %w", keyID, err)
	}

	logger.Debugf("Retrieving public key for key IRI [%s]", keyIRI)

	pubKey, err := r.pubKeyRetriever.GetPublicKey(keyIRI)
	if err != nil {
		logger.Errorf("Error retrieving public key for IRI [%s]: %s", keyIRI, err)

		return nil, fmt.Errorf("retrieve public key for ID [%s]: %w", keyID, err)
	}

	block, rest := pem.Decode([]byte(pubKey.PublicKeyPem))
	if block == nil {
		logger.Warnf("invalid public key: nil block. Rest: %s", rest)

		return nil, fmt.Errorf("invalid public key for ID [%s]: nil block", keyID)
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key for ID [%s]: %w", keyID, err)
	}

	return &ariesverifier.PublicKey{
		Type:  kms.ED25519, // TODO: Support other algorithms?
		Value: pk.(ed25519.PublicKey),
	}, nil
}

// SecretRetriever implements a custom key retriever to be used with the HTTP signature library.
type SecretRetriever struct{}

// Get returns a 'secret' that directs the HTTP signature library to use the custom SignatureHashAlgorithm above.
func (r *SecretRetriever) Get(keyID string) (httpsig.Secret, error) {
	return httpsig.Secret{
		KeyID:     keyID,
		Algorithm: orbHTTPSigAlgorithm,
	}, nil
}
