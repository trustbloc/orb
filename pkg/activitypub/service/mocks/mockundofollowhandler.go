/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"net/url"
)

// UndoFollowHandler implements a mock undo follow handler.
type UndoFollowHandler struct {
	err error
}

// NewUndoFollowHandler returns a mock undo follow handler.
func NewUndoFollowHandler() *UndoFollowHandler {
	return &UndoFollowHandler{}
}

// WithError injects an error.
func (m *UndoFollowHandler) WithError(err error) *UndoFollowHandler {
	m.err = err

	return m
}

// Undo removes follow request.
func (m *UndoFollowHandler) Undo(actor *url.URL) error {
	return m.err
}
