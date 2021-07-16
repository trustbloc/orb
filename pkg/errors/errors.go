/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"errors"
)

var (
	transientType = &transient{} //nolint:gochecknoglobals

	// ErrContentNotFound is used to indicate that content at a given address could not be found.
	ErrContentNotFound = errors.New("content not found")
)

// NewTransient returns a transient error that wraps the given error in order to indicate to the caller that a retry may
// resolve the problem, whereas a non-transient (persistent) error will always fail with the same outcome if retried.
func NewTransient(err error) error {
	return &transient{err: err}
}

// IsTransient returns true if the given error is a 'transient' error.
func IsTransient(err error) bool {
	return errors.As(err, &transientType)
}

type transient struct {
	err error
}

func (e *transient) Error() string {
	return e.err.Error()
}

func (e *transient) Unwrap() error {
	return e.err
}
