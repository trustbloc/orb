/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/anchor/subject"
)

// GetAnchorSubject returns anchor payload.
func GetAnchorSubject(node *verifiable.Credential) (*subject.Payload, error) {
	customFields, err := getCredentialSubjectCustomFields(node)
	if err != nil {
		return nil, err
	}

	customFieldsBytes, err := json.Marshal(customFields)
	if err != nil {
		return nil, err // nolint: wrapcheck
	}

	var payload subject.Payload

	err = json.Unmarshal(customFieldsBytes, &payload)
	if err != nil {
		return nil, err // nolint: wrapcheck
	}

	return &payload, nil
}

func getCredentialSubjectCustomFields(node *verifiable.Credential) (map[string]interface{}, error) {
	payload := node.Subject // nolint: ifshort
	if payload == nil {
		return nil, fmt.Errorf("missing credential subject")
	}

	switch t := payload.(type) {
	case []verifiable.Subject:
		payloads, _ := payload.([]verifiable.Subject) //nolint: errcheck

		return payloads[0].CustomFields, nil

	default:
		return nil, fmt.Errorf("unexpected interface for credential subject: %s", t)
	}
}
