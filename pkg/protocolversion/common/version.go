/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"errors"
	"strings"
)

// Version represents the protocol version string.
type Version string

// Matches returns true if the major and minor versions match. For example:
//
// 'v1' and 'v1.2.0' => false
// 'v1' and 'v1.0.0' => true
// 'v1' and 'v1.0.1' => true
// 'v1.0' and 'v1.0.1' => true
// 'v1.1' and 'v1.1.4' => true
// 'v1.1' and 'v1.2.0' => false.
func (v Version) Matches(other string) bool {
	p1 := strings.Split(string(v), ".")
	p2 := strings.Split(other, ".")

	var majorVersion1 string

	minorVersion1 := "0"

	var majorVersion2 string

	minorVersion2 := "0"

	if len(p1) > 0 {
		majorVersion1 = p1[0]
	}

	if len(p1) > 1 {
		minorVersion1 = p1[1]
	}

	if len(p2) > 0 {
		majorVersion2 = p2[0]
	}

	if len(p2) > 1 {
		minorVersion2 = p2[1]
	}

	return majorVersion1 == majorVersion2 && minorVersion1 == minorVersion2
}

// Validate validates the format of the version string.
func (v Version) Validate() error {
	p := strings.Split(string(v), ".")

	if len(p) == 0 || p[0] == "" {
		return errors.New("no version specified")
	}

	const v2 = 2

	if len(p) > v2 {
		return errors.New("version must only have a major and optional minor part (e.g. v1 or v1.1)")
	}

	return nil
}
