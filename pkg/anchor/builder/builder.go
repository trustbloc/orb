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
)

const (
	// this context is pre-loaded by aries framework.
	vcContextURIV1 = "https://www.w3.org/2018/credentials/v1"
)

// Params holds required parameters for building anchor credential.
type Params struct {
	Issuer string
	URL    string
}

// New returns new instance of anchor credential builder.
func New(params Params) (*Builder, error) {
	if err := verifyBuilderParams(params); err != nil {
		return nil, fmt.Errorf("failed to verify builder parameters: %w", err)
	}

	return &Builder{
		params: params,
	}, nil
}

// Builder implements building of anchor credential.
type Builder struct {
	params Params
}

// CredentialSubject contains the verifiable credential subject.
type CredentialSubject struct {
	ID string `json:"id"`
}

// Build will create and sign anchor credential.
func (b *Builder) Build(anchorHashlink string, context []string) (*verifiable.Credential, error) {
	id := b.params.URL + "/" + uuid.New().String()

	now := &util.TimeWrapper{Time: time.Now()}

	ctx := []string{vcContextURIV1}

	ctx = append(ctx, context...)

	vc := &verifiable.Credential{
		Types:   []string{"VerifiableCredential"},
		Context: ctx,
		Subject: &CredentialSubject{ID: anchorHashlink},
		Issuer: verifiable.Issuer{
			ID: b.params.Issuer,
		},
		Issued: now,
		ID:     id,
	}

	return vc, nil
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
