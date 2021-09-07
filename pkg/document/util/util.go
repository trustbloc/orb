/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"strings"

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
