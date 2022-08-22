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

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	ariessigner "github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
)

const (
	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// Ed25519Signature2020 ed25519 signature suite.
	Ed25519Signature2020 = "Ed25519Signature2020"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"

	ctxJWS                  = "https://w3id.org/security/suites/jws-2020/v1"
	ctxEd25519Signature2020 = "https://w3id.org/security/suites/ed25519-2020/v1"

	// AssertionMethod assertionMethod.
	AssertionMethod = "assertionMethod"
)

type metricsProvider interface {
	SignerSign(value time.Duration)
	SignerGetKey(value time.Duration)
	SignerAddLinkedDataProof(value time.Duration)
}

type keyManager interface {
	Get(keyID string) (interface{}, error)
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

// SigningParams contains required parameters for signing anchored credential.
type SigningParams struct {
	VerificationMethod string
	SignatureSuite     string
	Domain             string
}

// Providers contains all of the providers required by verifiable credential signer.
type Providers struct {
	DocLoader  ld.DocumentLoader
	KeyManager keyManager
	Crypto     crypto
	Metrics    metricsProvider
}

// New returns new instance of VC signer.
func New(providers *Providers, params SigningParams) (*Signer, error) {
	if err := verifySigningParams(params); err != nil {
		return nil, fmt.Errorf("failed to verify signing parameters: %w", err)
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

// Opt represents option for Sign fn.
type Opt func(*verifiable.LinkedDataProofContext)

// WithCreated allows providing time when signing credentials.
func WithCreated(t time.Time) Opt {
	return func(ctx *verifiable.LinkedDataProofContext) {
		ctx.Created = &t
	}
}

// WithSignatureRepresentation allows providing signature representation when signing credentials.
func WithSignatureRepresentation(signature verifiable.SignatureRepresentation) Opt {
	return func(ctx *verifiable.LinkedDataProofContext) {
		ctx.SignatureRepresentation = signature
	}
}

// WithDomain allows providing domain when signing credentials.
func WithDomain(domain string) Opt {
	return func(ctx *verifiable.LinkedDataProofContext) {
		ctx.Domain = domain
	}
}

// Sign will sign verifiable credential.
func (s *Signer) Sign(vc *verifiable.Credential, opts ...Opt) (*verifiable.Credential, error) {
	signingCtx, err := s.getLinkedDataProofContext(opts...)
	if err != nil {
		return nil, err
	}

	addLinkedDataProofStartTime := time.Now()

	err = vc.AddLinkedDataProof(signingCtx, jsonld.WithDocumentLoader(s.Providers.DocLoader))
	if err != nil {
		return nil, fmt.Errorf("failed to sign vc: %w", err)
	}

	s.Providers.Metrics.SignerAddLinkedDataProof(time.Since(addLinkedDataProofStartTime))

	return vc, nil
}

// Context return context.
func (s *Signer) Context() []string {
	if s.params.SignatureSuite == JSONWebSignature2020 {
		return []string{ctxJWS, ctxEd25519Signature2020}
	} else if s.params.SignatureSuite == Ed25519Signature2020 {
		return []string{ctxJWS, ctxEd25519Signature2020}
	}

	return []string{}
}

func (s *Signer) getLinkedDataProofContext(opts ...Opt) (*verifiable.LinkedDataProofContext, error) {
	kmsSigner, err := s.getKMSSigner()
	if err != nil {
		return nil, err
	}

	var signatureSuite ariessigner.SignatureSuite

	var signatureRepresentation verifiable.SignatureRepresentation

	switch s.params.SignatureSuite {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(suite.WithSigner(kmsSigner))
		signatureRepresentation = verifiable.SignatureProofValue
	case Ed25519Signature2020:
		signatureSuite = ed25519signature2020.New(suite.WithSigner(kmsSigner))
		signatureRepresentation = verifiable.SignatureProofValue
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(suite.WithSigner(kmsSigner))
		signatureRepresentation = verifiable.SignatureJWS
	default:
		return nil, fmt.Errorf("signature type not supported: %s", s.params.SignatureSuite)
	}

	now := time.Now()

	signingCtx := &verifiable.LinkedDataProofContext{
		Domain:                  s.params.Domain,
		VerificationMethod:      s.params.VerificationMethod,
		SignatureRepresentation: signatureRepresentation,
		SignatureType:           s.params.SignatureSuite,
		Suite:                   signatureSuite,
		Purpose:                 AssertionMethod,
		Created:                 &now,
	}

	for _, opt := range opts {
		opt(signingCtx)
	}

	return signingCtx, nil
}

// getKMSSigner returns new KMS signer based on verification method.
func (s *Signer) getKMSSigner() (signer, error) {
	kmsSigner, err := newKMSSigner(s.Providers.KeyManager, s.Providers.Crypto, s.params.VerificationMethod,
		s.Providers.Metrics)
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
	// Alg return alg.
	Alg() string
}

type kmsSigner struct {
	keyHandle interface{}
	crypto    crypto
	metrics   metricsProvider
}

func newKMSSigner(keyManager keyManager, c crypto, verificationMethod string,
	metrics metricsProvider) (*kmsSigner, error) {
	// verification will contain did key ID
	keyID, err := getKeyIDFromVerificationMethod(verificationMethod)
	if err != nil {
		return nil, err
	}

	getKeyStartTime := time.Now()

	keyHandler, err := keyManager.Get(keyID)
	if err != nil {
		return nil, err
	}

	metrics.SignerGetKey(time.Since(getKeyStartTime))

	return &kmsSigner{keyHandle: keyHandler, crypto: c, metrics: metrics}, nil
}

// Sign will sign bytes of data.
func (ks *kmsSigner) Sign(data []byte) ([]byte, error) {
	startTime := time.Now()
	defer func() { ks.metrics.SignerSign(time.Since(startTime)) }()

	v, err := ks.crypto.Sign(data, ks.keyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// Alg return alg.
func (ks *kmsSigner) Alg() string {
	return ""
}
