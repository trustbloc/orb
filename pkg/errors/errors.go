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
	// ErrContentNotFound is used to indicate that content at a given address could not be found.
	ErrContentNotFound = errors.New("content not found")

	// ErrWitnessesNotFound is used to indicate that no witnesses could not be found.
	ErrWitnessesNotFound = errors.New("witnesses not found")
)

// NewTransient returns a transient error that wraps the given error in order to indicate to the caller that a retry may
// resolve the problem, whereas a non-transient (persistent) error will always fail with the same outcome if retried.
func NewTransient(err error) error {
	return &transientError{err: err}
}

// NewTransientf returns a transient error in order to indicate to the caller that a retry may resolve the problem,
// whereas a non-transient (persistent) error will always fail with the same outcome if retried.
func NewTransientf(format string, a ...interface{}) error {
	return &transientError{err: fmt.Errorf(format, a...)}
}

// IsTransient returns true if the given error is a 'transient' error.
func IsTransient(err error) bool {
	errTransientType := &transientError{}

	return errors.As(err, &errTransientType)
}

// NewBadRequest returns a 'bad request' error that wraps the given error in order to indicate to the caller that
// the request was invalid.
func NewBadRequest(err error) error {
	return &badRequestError{err: err}
}

// NewBadRequestf returns a 'bad request' error in order to indicate to the caller that the request was invalid.
func NewBadRequestf(format string, a ...interface{}) error {
	return &badRequestError{err: fmt.Errorf(format, a...)}
}

// IsBadRequest returns true if the given error is a 'bad request' error.
func IsBadRequest(err error) bool {
	errInvalidRequestType := &badRequestError{}

	return errors.As(err, &errInvalidRequestType)
}

type transientError struct {
	err error
}

func (e *transientError) Error() string {
	return e.err.Error()
}

func (e *transientError) Unwrap() error {
	return e.err
}

type badRequestError struct {
	err error
}

func (e *badRequestError) Error() string {
	return e.err.Error()
}

func (e *badRequestError) Unwrap() error {
	return e.err
}
