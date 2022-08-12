/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	httpsig "github.com/igor-pavlenko/httpsignatures-go"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

type publicKeyRetriever interface {
	GetPublicKey(keyIRI *url.URL) (*vocab.PublicKeyType, error)
}

type actorRetriever interface {
	publicKeyRetriever

	GetActor(actorIRI *url.URL) (*vocab.ActorType, error)
}

type verifier interface {
	Verify(r *http.Request) error
}

// Verifier verifies signatures of HTTP requests.
type Verifier struct {
	actorRetriever actorRetriever
	verifier       func() verifier
}

// NewVerifier returns a new HTTP signature verifier.
func NewVerifier(actorRetriever actorRetriever, cr crypto, km keyManager) *Verifier {
	algo := NewVerifierAlgorithm(cr, km, NewKeyResolver(actorRetriever))
	secretRetriever := &SecretRetriever{}

	return &Verifier{
		actorRetriever: actorRetriever,
		verifier: func() verifier {
			// Return a new instance for each verification since the HTTP signature
			// implementation is not thread safe.
			hs := httpsig.NewHTTPSignatures(secretRetriever)
			hs.SetSignatureHashAlgorithm(algo)

			return hs
		},
	}
}

// VerifyRequest verifies the following:
// - HTTP signature on the request.
// - Ensures that the key ID in the request header is owned by the actor.
//
// Returns:
// - true if the signature was successfully verified, otherwise false.
// - Actor IRI if the signature was successfully verified.
// - An error if the signature could not be verified due to server error.
func (v *Verifier) VerifyRequest(req *http.Request) (bool, *url.URL, error) {
	logger.Debugf("Verifying request. Headers: %s", req.Header)

	verified, err := v.verify(req)
	if err != nil {
		return false, nil, err
	}

	if !verified {
		return false, nil, nil
	}

	keyID := getKeyIDFromSignatureHeader(req)
	if keyID == "" {
		logger.Debugf("'keyId' not found in Signature header in request %s", req.URL)

		return false, nil, nil
	}

	logger.Debugf("Verifying keyId [%s] from signature header ...", keyID)

	keyIRI, err := url.Parse(keyID)
	if err != nil {
		logger.Debugf("invalid public key ID [%s] in request %s: %s", keyID, req.URL, err)

		return false, nil, nil
	}

	publicKey, err := v.actorRetriever.GetPublicKey(keyIRI)
	if err != nil {
		return false, nil, fmt.Errorf("get public key [%s]: %w", keyIRI, err)
	}

	logger.Debugf("Retrieving actor for public key owner [%s]", publicKey.Owner)

	// Ensure that the public key ID matches the key ID of the specified owner. Otherwise, it could
	// be an attempt to impersonate an actor.
	actor, err := v.actorRetriever.GetActor(publicKey.Owner())
	if err != nil {
		return false, nil, fmt.Errorf("get actor [%s]: %w", publicKey.Owner(), err)
	}

	if actor.PublicKey() == nil {
		logger.Debugf("nil public key on actor [%s] in request %s: %s", actor.ID(), req.URL)

		return false, nil, nil
	}

	if actor.PublicKey().ID().String() != publicKey.ID().String() {
		logger.Debugf("public key [%s] of actor [%s] does not match the provided public key ID [%s] in request %s",
			actor.PublicKey().ID(), actor.ID(), publicKey.ID(), req.URL)

		return false, nil, nil
	}

	logger.Debugf("Successfully verified signature in header. Actor [%s]", actor.ID())

	return true, actor.ID().URL(), nil
}

func (v *Verifier) verify(req *http.Request) (bool, error) {
	err := v.verifier().Verify(req)
	if err == nil {
		return true, nil
	}

	if orberrors.IsTransient(err) {
		logger.Errorf("Error in signature verification for request %s: %s", req.URL, err)

		return false, err
	}

	if strings.Contains(err.Error(), "transient http error:") {
		logger.Errorf("Error in signature verification for request %s: %s", req.URL, err)

		// The http sig library does not wrap errors properly, so the ORB transient error is not in the
		// chain of errors. Wrap the error with a transient error so that the request may be retried by
		// the caller
		return false, orberrors.NewTransient(err)
	}

	logger.Infof("Signature verification failed for request %s: %s", req.URL, err)

	return false, nil
}

func getKeyIDFromSignatureHeader(req *http.Request) string {
	signatureHeader, ok := req.Header["Signature"]
	if !ok || len(signatureHeader) == 0 {
		logger.Debugf("'Signature' not found in request header for request %s", req.URL)

		return ""
	}

	var keyID string

	const kvLength = 2

	for _, v := range signatureHeader {
		for _, kv := range strings.Split(v, ",") {
			parts := strings.Split(kv, "=")
			if len(parts) != kvLength {
				continue
			}

			if parts[0] == "keyId" {
				keyID = strings.ReplaceAll(parts[1], `"`, "")
			}
		}
	}

	return keyID
}
