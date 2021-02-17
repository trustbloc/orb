/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package builder

import (
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/anchor/txn"
)

const (
	defVCContext = "https://www.w3.org/2018/credentials/v1"
	// TODO: Add context for anchor credential and define credential subject attributes there.
)

// Params holds required parameters for building anchor credential.
type Params struct {
	Issuer string
}

// New returns new instance of anchor credential builder.
func New(signer vcSigner, params Params) (*Builder, error) {
	if err := verifyBuilderParams(params); err != nil {
		return nil, fmt.Errorf("failed to verify builder parameters: %s", err.Error())
	}

	return &Builder{
		signer: signer,
		params: params,
	}, nil
}

type vcSigner interface {
	Sign(vc *verifiable.Credential) (*verifiable.Credential, error)
}

// Builder implements building of anchor credential.
type Builder struct {
	signer vcSigner
	params Params
}

// Build will create and sign anchor credential.
func (b *Builder) Build(subject *txn.Payload) (*verifiable.Credential, error) {
	vc := &verifiable.Credential{
		// TODO: Add definition for "AnchorCredential"
		Types:   []string{"VerifiableCredential"},
		Context: []string{defVCContext},
		Subject: subject,
		Issuer: verifiable.Issuer{
			ID: b.params.Issuer,
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
	}

	signedVC, err := b.signer.Sign(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to sign credential: %s", err.Error())
	}

	return signedVC, nil
}

func verifyBuilderParams(params Params) error {
	if params.Issuer == "" {
		return errors.New("missing issuer")
	}

	return nil
}
