/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"encoding/json"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
)

const (
	longFormOrCIDSeparator = ":"
	didSeparator           = ":"
)

// Parser is an operation parser.
type Parser struct {
	coreParser protocol.OperationParser
}

// New returns a new operation parser.
func New(parser protocol.OperationParser) *Parser {
	return &Parser{coreParser: parser}
}

// Parse parses and validates operation.
func (p *Parser) Parse(namespace string, operationBuffer []byte) (*operation.Operation, error) {
	return p.coreParser.Parse(namespace, operationBuffer)
}

// GetRevealValue returns this operation reveal value.
func (p *Parser) GetRevealValue(opBytes []byte) (string, error) {
	return p.coreParser.GetRevealValue(opBytes)
}

// GetCommitment returns next operation commitment.
func (p *Parser) GetCommitment(opBytes []byte) (string, error) {
	return p.coreParser.GetCommitment(opBytes)
}

// ParseDID inspects resolution request and returns:
// - did and create request in case of long form resolution
// - just did in case of short form resolution (common scenario).
func (p *Parser) ParseDID(namespace, shortOrLongFormDID string) (string, []byte, error) {
	withoutNamespace := strings.ReplaceAll(shortOrLongFormDID, namespace+didSeparator, "")
	posLongFormSeparator := strings.Index(withoutNamespace, longFormOrCIDSeparator)

	if posLongFormSeparator == -1 {
		// there is short form did (without cid)
		return shortOrLongFormDID, nil, nil
	}

	// long form format: '<namespace>:<unique-portion>:Base64url(JCS({suffix-data, delta}))'
	// orb format: '<namespace>:<cid>:<unique-portion>'
	endOfDIDPosOrEndOfCID := strings.LastIndex(shortOrLongFormDID, longFormOrCIDSeparator)

	lastPart := shortOrLongFormDID[endOfDIDPosOrEndOfCID+1:]

	// if last part is encoded JSON then it is long-form did
	if isEncodedJSON(lastPart) {
		return p.coreParser.ParseDID(namespace, shortOrLongFormDID)
	}

	// return did with CID
	return shortOrLongFormDID, nil, nil
}

func isEncodedJSON(part string) bool {
	decodedJCS, err := encoder.DecodeString(part)
	if err != nil {
		return false
	}

	var js map[string]interface{}

	return json.Unmarshal(decodedJCS, &js) == nil
}
