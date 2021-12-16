/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package errors

import (
	"errors"
	"fmt"
)

var (
	transientType = &transient{} //nolint:gochecknoglobals

	invalidRequestType = &badRequest{} //nolint:gochecknoglobals

	// ErrContentNotFound is used to indicate that content at a given address could not be found.
	ErrContentNotFound = errors.New("content not found")
)

// NewTransient returns a transient error that wraps the given error in order to indicate to the caller that a retry may
// resolve the problem, whereas a non-transient (persistent) error will always fail with the same outcome if retried.
func NewTransient(err error) error {
	return &transient{err: err}
}

// NewTransientf returns a transient error in order to indicate to the caller that a retry may resolve the problem,
// whereas a non-transient (persistent) error will always fail with the same outcome if retried.
func NewTransientf(format string, a ...interface{}) error {
	return &transient{err: fmt.Errorf(format, a...)}
}

// IsTransient returns true if the given error is a 'transient' error.
func IsTransient(err error) bool {
	return errors.As(err, &transientType)
}

// NewBadRequest returns a 'bad request' error that wraps the given error in order to indicate to the caller that
// the request was invalid.
func NewBadRequest(err error) error {
	return &badRequest{err: err}
}

// NewBadRequestf returns a 'bad request' error in order to indicate to the caller that the request was invalid.
func NewBadRequestf(format string, a ...interface{}) error {
	return &badRequest{err: fmt.Errorf(format, a...)}
}

// IsBadRequest returns true if the given error is a 'bad request' error.
func IsBadRequest(err error) bool {
	return errors.As(err, &invalidRequestType)
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

type badRequest struct {
	err error
}

func (e *badRequest) Error() string {
	return e.err.Error()
}

func (e *badRequest) Unwrap() error {
	return e.err
}
