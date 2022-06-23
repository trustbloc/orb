/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

// AllowedOriginsStore is a mock, allowed origins store.
type AllowedOriginsStore struct {
	allowedOrigins []*url.URL
	err            error
}

// NewAllowedOriginsStore returns a mock, allowed origins store.
func NewAllowedOriginsStore() *AllowedOriginsStore {
	return &AllowedOriginsStore{}
}

// FromString initializes the origin URIs from the given strings.
func (m *AllowedOriginsStore) FromString(values ...string) *AllowedOriginsStore {
	m.allowedOrigins = make([]*url.URL, len(values))

	for i, origin := range values {
		m.allowedOrigins[i] = testutil.MustParseURL(origin)
	}

	return m
}

// WithError sets an error for testing.
func (m *AllowedOriginsStore) WithError(err error) *AllowedOriginsStore {
	m.err = err

	return m
}

// Get returns the anchor origins or an error.
func (m *AllowedOriginsStore) Get() ([]*url.URL, error) {
	if m.err != nil {
		return nil, m.err
	}

	return m.allowedOrigins, nil
}
