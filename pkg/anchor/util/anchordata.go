/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	delimiter    = "."
	allowedParts = 2
)

var integerRegex = regexp.MustCompile(`^[1-9]\d*$`)

// AnchorData holds anchored data.
type AnchorData struct {
	OperationCount   uint64
	CoreIndexFileURI string
}

// ParseAnchorString will parse anchor string into anchor data model.
func ParseAnchorString(anchor string) (*AnchorData, error) {
	parts := strings.Split(anchor, delimiter)

	if len(parts) != allowedParts {
		return nil, fmt.Errorf("parse anchor data[%s] failed: expecting [%d] parts, got [%d] parts",
			anchor, allowedParts, len(parts))
	}

	ok := integerRegex.MatchString(parts[0])
	if !ok {
		return nil, fmt.Errorf("parse anchor data[%s] failed: number of operations must be positive integer", anchor)
	}

	opsNum, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse anchor data[%s] failed: %w", anchor, err)
	}

	return &AnchorData{
		OperationCount:   opsNum,
		CoreIndexFileURI: parts[1],
	}, nil
}

// GetAnchorString will create anchor string from anchor data.
func (ad *AnchorData) GetAnchorString() string {
	return fmt.Sprintf("%d", ad.OperationCount) + delimiter + ad.CoreIndexFileURI
}
