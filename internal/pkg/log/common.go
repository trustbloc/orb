/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"github.com/trustbloc/logutil-go/pkg/log"
	"go.uber.org/zap"
)

// InvalidParameterValue outputs an 'invalid parameter' log to the given logger.
func InvalidParameterValue(l *log.Log, param string, err error) {
	l.WithOptions(zap.AddCallerSkip(1)).Error("Invalid parameter value", WithParameter(param), log.WithError(err))
}

// CloseIteratorError outputs a 'close iterator' error log to the given logger.
func CloseIteratorError(l *log.Log, err error) {
	l.WithOptions(zap.AddCallerSkip(1)).Warn("Error closing iterator", log.WithError(err))
}

// CloseResponseBodyError outputs a 'close response body' error log to the given logger.
func CloseResponseBodyError(l *log.Log, err error) {
	l.WithOptions(zap.AddCallerSkip(1)).Warn("Error closing response body", log.WithError(err))
}

// ReadRequestBodyError outputs a 'read response body' error log to the given logger.
func ReadRequestBodyError(l *log.Log, err error) {
	l.WithOptions(zap.AddCallerSkip(1)).Error("Error reading request body", log.WithError(err))
}

// WriteResponseBodyError outputs a 'write response body' error log to the given logger.
func WriteResponseBodyError(l *log.Log, err error) {
	l.WithOptions(zap.AddCallerSkip(1)).Error("Error writing response body", log.WithError(err))
}

// WroteResponse outputs a 'wrote response' log to the given logger.
func WroteResponse(l *log.Log, data []byte) {
	l.WithOptions(zap.AddCallerSkip(1)).Debug("Wrote response", log.WithResponse(data))
}
