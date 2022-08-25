/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/linkset"
)

// VerifiableCredentialFromAnchorLink validates the AnchorEvent and returns the embedded verifiable credential.
func VerifiableCredentialFromAnchorLink(anchorLink *linkset.Link,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	if err := anchorLink.Validate(); err != nil {
		return nil, fmt.Errorf("invalid anchor link: %w", err)
	}

	if anchorLink.Replies() == nil {
		return nil, fmt.Errorf("no replies in anchor link")
	}

	vcBytes, err := anchorLink.Replies().Content()
	if err != nil {
		return nil, fmt.Errorf("unmarshal reply: %w", err)
	}

	vc, err := verifiable.ParseCredential(vcBytes, append(opts, verifiable.WithStrictValidation())...)
	if err != nil {
		if strings.Contains(err.Error(), "http request unsuccessful") ||
			strings.Contains(err.Error(), "http server returned status code") ||
			strings.Contains(err.Error(), "database error getting public key for issuer") {
			// The server is probably down. Return a transient error so that it may be retried.
			return nil, errors.NewTransientf("parse credential: %w", err)
		}

		return nil, fmt.Errorf("parse credential: %w", err)
	}

	return vc, nil
}
