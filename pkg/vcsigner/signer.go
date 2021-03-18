/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcsigner

import (
	"errors"
	"fmt"
	"strings"
	"time"

	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/piprate/json-gold/ld"
)

const (
	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"

	// AssertionMethod assertionMethod.
	AssertionMethod = "assertionMethod"
)

// SigningParams contains required parameters for signing anchored credential.
type SigningParams struct {
	VerificationMethod string
	SignatureSuite     string
	Domain             string
}

// Providers contains all of the providers required by verifiable credential signer.
type Providers struct {
	DocLoader  ld.DocumentLoader
	KeyManager kms.KeyManager
	Crypto     ariescrypto.Crypto
}

// New returns new instance of VC signer.
func New(providers *Providers, params SigningParams) (*Signer, error) {
	if err := verifySigningParams(params); err != nil {
		return nil, fmt.Errorf("failed to verify signing parameters: %s", err.Error())
	}

	return &Signer{
		Providers: providers,
		params:    params,
	}, nil
}

func verifySigningParams(params SigningParams) error {
	if params.VerificationMethod == "" {
		return errors.New("missing verification method")
	}

	if params.SignatureSuite == "" {
		return errors.New("missing signature suite")
	}

	if params.Domain == "" {
		return errors.New("missing domain")
	}

	return nil
}

// Signer to sign verifiable credential.
type Signer struct {
	*Providers
	params SigningParams
}

// Sign will sign verifiable credential.
func (s *Signer) Sign(vc *verifiable.Credential) (*verifiable.Credential, error) {
	signingCtx, err := s.getLinkedDataProofContext()
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(s.Providers.DocLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	return vc, nil
}

func (s *Signer) getLinkedDataProofContext() (*verifiable.LinkedDataProofContext, error) {
	kmsSigner, err := s.getKMSSigner()
	if err != nil {
		return nil, err
	}

	var signatureSuite ariessigner.SignatureSuite

	switch s.params.SignatureSuite {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(kmsSigner))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(kmsSigner))
	default:
		return nil, fmt.Errorf("signature type not supported: %s", s.params.SignatureSuite)
	}

	now := time.Now()

	signingCtx := &verifiable.LinkedDataProofContext{
		Domain:                  s.params.Domain,
		VerificationMethod:      s.params.VerificationMethod,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           s.params.SignatureSuite,
		Suite:                   signatureSuite,
		Purpose:                 AssertionMethod,
		Created:                 &now,
	}

	return signingCtx, nil
}

// getKMSSigner returns new KMS signer based on verification method.
func (s *Signer) getKMSSigner() (signer, error) {
	kmsSigner, err := newKMSSigner(s.Providers.KeyManager, s.Providers.Crypto, s.params.VerificationMethod)
	if err != nil {
		return nil, err
	}

	return kmsSigner, nil
}

// getKeyIDFromVerificationMethod fetches key ID from the verification method.
func getKeyIDFromVerificationMethod(verificationMethod string) (string, error) {
	const partNum = 2

	parts := strings.Split(verificationMethod, "#")
	if len(parts) != partNum {
		return "", fmt.Errorf("invalid verification method format")
	}

	return parts[1], nil
}

type signer interface {
	// Sign will sign data and return signature
	Sign(data []byte) ([]byte, error)
}

type kmsSigner struct {
	keyHandle interface{}
	crypto    ariescrypto.Crypto
}

func newKMSSigner(keyManager kms.KeyManager, c ariescrypto.Crypto, verificationMethod string) (*kmsSigner, error) {
	// verification will contain did key ID
	keyID, err := getKeyIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	keyHandler, err := keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{keyHandle: keyHandler, crypto: c}, nil
}

// Sign will sign bytes of data.
func (ks *kmsSigner) Sign(data []byte) ([]byte, error) {
	v, err := ks.crypto.Sign(data, ks.keyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}
