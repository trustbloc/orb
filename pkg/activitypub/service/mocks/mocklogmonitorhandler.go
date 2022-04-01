/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
)

// AcceptFollowHandler implements a mock accept follow handler.
type AcceptFollowHandler struct {
	err error
}

// NewAcceptFollowHandler returns a mock accept follow handler.
func NewAcceptFollowHandler() *AcceptFollowHandler {
	return &AcceptFollowHandler{}
}

// WithError injects an error.
func (m *AcceptFollowHandler) WithError(err error) *AcceptFollowHandler {
	m.err = err

	return m
}

// Accept accepts/rejects follow request.
func (m *AcceptFollowHandler) Accept(actor *url.URL) error {
	return m.err
}
