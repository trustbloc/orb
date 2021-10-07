/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// VerifiableCredentialFromAnchorEvent validates and returns the verifiable credential embedded in the
// given anchor event.
func VerifiableCredentialFromAnchorEvent(anchorEvent *vocab.AnchorEventType,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	if err := anchorEvent.Validate(); err != nil {
		return nil, fmt.Errorf("invalid anchor event: %w", err)
	}

	vcBytes, err := json.Marshal(anchorEvent.Witness())
	if err != nil {
		return nil, fmt.Errorf("marshal witness: %w", err)
	}

	vc, err := verifiable.ParseCredential(vcBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("parse credential: %w", err)
	}

	return vc, nil
}
