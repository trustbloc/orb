/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

// MinOrbIdentifierParts is minimum number of parts in Orb identifier.
const MinOrbIdentifierParts = 4

// GetSuffix returns suffix from id.
func GetSuffix(id string) (string, error) {
	parts := strings.Split(id, docutil.NamespaceDelimiter)

	if len(parts) < MinOrbIdentifierParts {
		return "", fmt.Errorf("invalid number of parts[%d] for Orb identifier", len(parts))
	}

	// suffix is always the last part
	suffix := parts[len(parts)-1]

	return suffix, nil
}

// BetweenStrings returns string between first and second string.
func BetweenStrings(value, first, second string) (string, error) {
	posFirst := strings.Index(value, first)
	if posFirst == -1 {
		return "", fmt.Errorf("string '%s' doesn't contain first string '%s'", value, first)
	}

	posSecond := strings.Index(value, second)
	if posSecond == -1 {
		return "", fmt.Errorf("string '%s' doesn't contain second string '%s'", value, second)
	}

	posFirstAdjusted := posFirst + len(first)
	if posFirstAdjusted >= posSecond {
		return "", fmt.Errorf("second string '%s' is before first string '%s' in string '%s'", second, first, value)
	}

	return value[posFirstAdjusted:posSecond], nil
}

// GetOperationsAfterCanonicalReference retrieves operations after canonical references.
// assumption: operations are sorted by transaction time
func GetOperationsAfterCanonicalReference(ref string, anchorOps []*operation.AnchoredOperation) []*operation.AnchoredOperation { //nolint:lll
	found := false

	var additionalAnchorOps []*operation.AnchoredOperation

	for _, anchorOp := range anchorOps {
		if found {
			additionalAnchorOps = append(additionalAnchorOps, anchorOp)
		}

		if anchorOp.CanonicalReference == ref {
			found = true
		}
	}

	return additionalAnchorOps
}

// GetPublishedOperationsFromMetadata will retrieve published operations from metadata.
func GetPublishedOperationsFromMetadata(metadata document.Metadata) ([]*operation.AnchoredOperation, error) {
	methodMetadata, err := GetMethodMetadata(metadata)
	if err != nil {
		return nil, err
	}

	return getOperationsByKey(methodMetadata, document.PublishedOperationsProperty)
}

// GetUnpublishedOperationsFromMetadata will retrieve unpublished operations from metadata.
func GetUnpublishedOperationsFromMetadata(metadata document.Metadata) ([]*operation.AnchoredOperation, error) {
	methodMetadata, err := GetMethodMetadata(metadata)
	if err != nil {
		return nil, err
	}

	return getOperationsByKey(methodMetadata, document.UnpublishedOperationsProperty)
}

// GetMethodMetadata retrieves method metadata from document metadata.
func GetMethodMetadata(metadata document.Metadata) (map[string]interface{}, error) {
	if metadata == nil {
		return nil, fmt.Errorf("missing document metadata")
	}

	methodMetadataObj, ok := metadata[document.MethodProperty]
	if !ok {
		return nil, fmt.Errorf("missing method metadata")
	}

	switch val := methodMetadataObj.(type) {
	case document.Metadata:
		return val, nil
	case map[string]interface{}:
		return val, nil
	default:
		return nil, fmt.Errorf("method metadata is wrong type[%T]", methodMetadataObj)
	}
}

func getOperationsByKey(methodMetadata map[string]interface{}, key string) ([]*operation.AnchoredOperation, error) {
	opsObj, ok := methodMetadata[key]
	if !ok {
		return nil, fmt.Errorf("key[%s] not found in method metadata", key)
	}

	opsBytes, err := json.Marshal(opsObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal '%s'", key)
	}

	var ops []*operation.AnchoredOperation

	err = json.Unmarshal(opsBytes, &ops)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal '%s'", key)
	}

	return ops, nil
}
