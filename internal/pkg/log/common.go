/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import "go.uber.org/zap"

// InvalidParameterValue outputs an 'invalid parameter' log to the given logger.
func InvalidParameterValue(log *Log, param string, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Error("Invalid parameter value", WithParameter(param), WithError(err))
}

// CloseIteratorError outputs a 'close iterator' error log to the given logger.
func CloseIteratorError(log *Log, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Warn("Error closing iterator", WithError(err))
}

// CloseResponseBodyError outputs a 'close response body' error log to the given logger.
func CloseResponseBodyError(log *Log, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Warn("Error closing response body", WithError(err))
}

// ReadRequestBodyError outputs a 'read response body' error log to the given logger.
func ReadRequestBodyError(log *Log, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Error("Error reading request body", WithError(err))
}

// WriteResponseBodyError outputs a 'write response body' error log to the given logger.
func WriteResponseBodyError(log *Log, err error) {
	log.WithOptions(zap.AddCallerSkip(1)).Error("Error writing response body", WithError(err))
}

// WroteResponse outputs a 'wrote response' log to the given logger.
func WroteResponse(log *Log, data []byte) {
	log.WithOptions(zap.AddCallerSkip(1)).Debug("Wrote response", WithResponse(data))
}
