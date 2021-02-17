/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/anchor/txn"
)

// GetTransactionPayload returns transaction payload.
func GetTransactionPayload(node *verifiable.Credential) (*txn.Payload, error) {
	customFields, err := getCredentialSubjectCustomFields(node)
	if err != nil {
		return nil, err
	}

	customFieldsBytes, err := json.Marshal(customFields)
	if err != nil {
		return nil, err
	}

	var payload txn.Payload

	err = json.Unmarshal(customFieldsBytes, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil
}

func getCredentialSubjectCustomFields(node *verifiable.Credential) (map[string]interface{}, error) {
	subject := node.Subject
	if subject == nil {
		return nil, fmt.Errorf("missing credential subject")
	}

	switch t := subject.(type) {
	case []verifiable.Subject:
		subjects, _ := subject.([]verifiable.Subject) //nolint: errcheck

		return subjects[0].CustomFields, nil

	default:
		return nil, fmt.Errorf("unexpected interface for credential subject: %s", t)
	}
}
