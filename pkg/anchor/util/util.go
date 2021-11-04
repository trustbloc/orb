/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/errors"
)

// VerifiableCredentialFromAnchorEvent validates the AnchorEvent and returns the embedded verifiable credential.
func VerifiableCredentialFromAnchorEvent(anchorEvent *vocab.AnchorEventType,
	opts ...verifiable.CredentialOpt) (*verifiable.Credential, error) {
	if err := anchorEvent.Validate(); err != nil {
		return nil, fmt.Errorf("invalid anchor event: %w", err)
	}

	witnessDoc, err := GetWitnessDoc(anchorEvent)
	if err != nil {
		return nil, fmt.Errorf("get witness from anchor event: %w", err)
	}

	vcBytes, err := json.Marshal(witnessDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal witness: %w", err)
	}

	vc, err := verifiable.ParseCredential(vcBytes, opts...)
	if err != nil {
		if strings.Contains(err.Error(), "http request unsuccessful") {
			// The server is probably down. Return a transient error so that it may be retried.
			return nil, errors.NewTransient(fmt.Errorf("http error during parse credential: %w", err))
		}

		return nil, fmt.Errorf("parse credential: %w", err)
	}

	return vc, nil
}

// GetWitnessDoc returns the 'witness' content object in the given anchor event.
func GetWitnessDoc(anchorEvent *vocab.AnchorEventType) (vocab.Document, error) {
	indexAnchorObj, err := anchorEvent.AnchorObject(anchorEvent.Index())
	if err != nil {
		return nil, fmt.Errorf("get anchor object for index [%s]: %w", anchorEvent.Index(), err)
	}

	tags := indexAnchorObj.Tag()

	if len(tags) == 0 {
		return nil, fmt.Errorf("anchor object [%s] does not contain a 'tag' field", anchorEvent.Index())
	}

	link := indexAnchorObj.Tag()[0].Link()
	if link == nil || !link.Rel().Is(vocab.RelationshipWitness) {
		return nil, fmt.Errorf("anchor object [%s] does not contain a tag of type 'Link' and 'rel' 'witness'",
			anchorEvent.Index())
	}

	witnessAnchorObj, err := anchorEvent.AnchorObject(link.HRef())
	if err != nil {
		return nil, fmt.Errorf("witness [%s] not found in anchor event", link.HRef())
	}

	return witnessAnchorObj.ContentObject(), nil
}
