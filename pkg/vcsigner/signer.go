/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcsigner

import (
	"fmt"
	"strings"
	"time"

	ariescrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"

	// AssertionMethod assertionMethod.
	AssertionMethod = "assertionMethod"
)

// New returns new instance of VC signer.
func New(keyManager kms.KeyManager, c ariescrypto.Crypto, verificationMethod, signatureType string) *Signer {
	return &Signer{
		keyManager:         keyManager,
		crypto:             c,
		verificationMethod: verificationMethod,
		signatureType:      signatureType,
	}
}

// Signer to sign verifiable credential.
type Signer struct {
	keyManager         kms.KeyManager
	crypto             ariescrypto.Crypto
	verificationMethod string
	signatureType      string
}

// Sign will sign verifiable credential.
func (s *Signer) Sign(vc *verifiable.Credential) (*verifiable.Credential, error) {
	signingCtx, err := s.getLinkedDataProofContext()
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(signingCtx)
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

	switch s.signatureType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(kmsSigner))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(kmsSigner))
	default:
		return nil, fmt.Errorf("signature type not supported %s", s.signatureType)
	}

	now := time.Now()

	signingCtx := &verifiable.LinkedDataProofContext{
		VerificationMethod:      s.verificationMethod,
		SignatureRepresentation: verifiable.SignatureJWS,
		SignatureType:           s.signatureType,
		Suite:                   signatureSuite,
		Purpose:                 AssertionMethod,
		Created:                 &now,
	}

	return signingCtx, nil
}

// getKMSSigner returns new KMS signer based on verification method.
func (s *Signer) getKMSSigner() (signer, error) {
	kmsSigner, err := newKMSSigner(s.keyManager, s.crypto, s.verificationMethod)
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
