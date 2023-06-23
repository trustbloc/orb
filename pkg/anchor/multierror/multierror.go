/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package multierror

// Error contains multiple errors mapped by unique suffix.
type Error struct {
	errors map[string]error
}

// New returns a new multi-error which contains a map of errors whose key is the unique DID suffix.
func New() *Error {
	return &Error{
		errors: make(map[string]error),
	}
}

// Error implements the error interface.
func (e *Error) Error() string {
	// Return an arbitrary error.
	for _, err := range e.errors {
		return err.Error()
	}

	return ""
}

// Errors returns the map of suffix errors.
func (e *Error) Errors() map[string]error {
	if e == nil {
		return nil
	}

	return e.errors
}

// Set sets the error for the given suffix.
func (e *Error) Set(suffix string, err error) {
	e.errors[suffix] = err
}
