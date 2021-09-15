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

	"github.com/trustbloc/orb/pkg/anchor/activity"
	"github.com/trustbloc/orb/pkg/anchor/subject"
)

const (
	// this context is pre-loaded by aries framework.
	vcContextURIV1 = "https://www.w3.org/2018/credentials/v1"
	// anchorContextURIV1 is anchor credential context URI.
	anchorContextURIV1 = "https://w3id.org/activityanchors/v1"
	// activity streams context.
	activityStreamsURI = "https://www.w3.org/ns/activitystreams"
	// jwsContextURIV1 is jws context.
	jwsContextURIV1 = "https://w3id.org/security/jws/v1"
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

// Build will create and sign anchor credential.
func (b *Builder) Build(payload *subject.Payload) (*verifiable.Credential, error) {
	id := b.params.URL + "/" + uuid.New().String()

	now := &util.TimeWrapper{Time: time.Now()}
	payload.Published = now

	anchorActivity, err := activity.BuildActivityFromPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to build anchor activity: %w", err)
	}

	vc := &verifiable.Credential{
		Types: []string{"VerifiableCredential", "AnchorCredential"},
		Context: []string{
			vcContextURIV1,
			activityStreamsURI,
			anchorContextURIV1,
			jwsContextURIV1,
		},
		Subject: anchorActivity,
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
