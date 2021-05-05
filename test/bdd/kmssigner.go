/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	httpsig "github.com/igor-pavlenko/httpsignatures-go"
)

const orbHTTPSigAlgorithm = "https://github.com/trustbloc/orb/httpsig"

type kmsSigner struct {
	client *http.Client
	cr     crypto.Crypto
	kms    kms.KeyManager
	keyID  string
}

func newKMSSigner(keystoreURL, keyID string, client *http.Client) *kmsSigner {
	return &kmsSigner{
		client: client,
		keyID:  keyID,
		cr:     webcrypto.New(keystoreURL, client),
		kms:    webkms.New(keystoreURL, client),
	}
}

func (s *kmsSigner) sign(pubKeyID string, req *http.Request) error {
	var headers []string

	if req.Method == http.MethodPost {
		headers = []string{"(request-target)", "Date", "Digest"}
	} else {
		headers = []string{"(request-target)", "Date"}
	}

	hs := httpsig.NewHTTPSignatures(&secretRetriever{})
	hs.SetDefaultSignatureHeaders(headers)
	hs.SetSignatureHashAlgorithm(newSignatureHashAlgorithm(s.cr, s.kms, s.keyID))

	req.Header.Add("Date", date())

	err := hs.Sign(pubKeyID, req)
	if err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	logger.Infof("Signed request for %s. Header: %s", req.URL, req.Header)

	return nil
}

type secretRetriever struct {
}

func (r *secretRetriever) Get(keyID string) (httpsig.Secret, error) {
	return httpsig.Secret{
		KeyID:     keyID,
		Algorithm: orbHTTPSigAlgorithm,
	}, nil
}

type signatureHashAlgorithm struct {
	Crypto crypto.Crypto
	KMS    kms.KeyManager
	KeyID  string
}

func newSignatureHashAlgorithm(c crypto.Crypto, kms kms.KeyManager, keyID string) *signatureHashAlgorithm {
	return &signatureHashAlgorithm{
		Crypto: c,
		KMS:    kms,
		KeyID:  keyID,
	}
}

// Algorithm returns this algorithm's name.
func (a *signatureHashAlgorithm) Algorithm() string {
	return orbHTTPSigAlgorithm
}

// Create signs data with the secret.
func (a *signatureHashAlgorithm) Create(secret httpsig.Secret, data []byte) ([]byte, error) {
	logger.Infof("Public key ID [%s], KMS key ID [%s]", secret.KeyID, a.KeyID)

	kh, err := a.KMS.Get(a.KeyID)
	if err != nil {
		return nil, fmt.Errorf("get key handle: %w", err)
	}

	logger.Infof("Got key handle for key ID [%s]: %+v. Signing ...", a.KeyID, kh)

	sig, err := a.Crypto.Sign(data, kh)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}

	logger.Infof("... successfully signed data with KeyID from KMS [%s]", a.KeyID)

	return sig, nil
}

// Verify verifies the signature over data with the secret.
func (a *signatureHashAlgorithm) Verify(secret httpsig.Secret, data, signature []byte) error {
	panic("not implemented")
}
