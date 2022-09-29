/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import "go.uber.org/zap"

type loggerFunc func(msg string, fields ...zap.Field)

// InvalidParameterValue outputs an 'invalid parameter' log to the given logger.
func InvalidParameterValue(log loggerFunc, param string, err error) {
	log("Invalid parameter value", WithParameter(param), WithError(err))
}

// CloseIteratorError outputs a 'close iterator' error log to the given logger.
func CloseIteratorError(log loggerFunc, err error) {
	log("Error closing iterator", WithError(err))
}

// CloseResponseBodyError outputs a 'close response body' error log to the given logger.
func CloseResponseBodyError(log loggerFunc, err error) {
	log("Error closing response body", WithError(err))
}

// WriteResponseBodyError outputs a 'write response body' error log to the given logger.
func WriteResponseBodyError(log loggerFunc, err error) {
	log("Error writing response body", WithError(err))
}

// WroteResponse outputs a 'wrote response' log to the given logger.
func WroteResponse(log loggerFunc, data []byte) {
	log("Wrote response", WithResponse(data))
}
