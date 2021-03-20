/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package builder

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/anchor/subject"
)

// Params holds required parameters for building anchor credential.
type Params struct {
	Issuer string
	URL    string
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
func (b *Builder) Build(payload *subject.Payload) (*verifiable.Credential, error) {
	id := b.params.URL + "/" + uuid.New().String()

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential", "AnchorCredential"},
		Context: []string{vcContextURIV1, AnchorContextURIV1, JwsContextURIV1},
		Subject: payload,
		Issuer: verifiable.Issuer{
			ID: b.params.Issuer,
		},
		Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		ID:     id,
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

	if params.URL == "" {
		return errors.New("missing URL")
	}

	return nil
}
