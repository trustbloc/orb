/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

// WebFingerResolver implements a mock WebFinger resolver.
type WebFingerResolver struct {
	Err error
	URI string
}

// ResolveHostMetaLink returns either the specified error, the specified URI, otherwise, if neither were specified
// then the URI in the argument is returned.
func (m *WebFingerResolver) ResolveHostMetaLink(uri, _ string) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}

	if m.URI != "" {
		return m.URI, nil
	}

	return uri, nil
}
