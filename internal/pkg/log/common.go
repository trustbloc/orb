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

// CloseIterator outputs a 'close iterator' error log to the given logger.
func CloseIterator(log loggerFunc, err error) {
	log("Error closing iterator", WithError(err))
}

// CloseResponseBody outputs an 'close respojnse body' error log to the given logger.
func CloseResponseBody(log loggerFunc, err error) {
	log("Error closing response body", WithError(err))
}
