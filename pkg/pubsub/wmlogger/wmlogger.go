/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wmlogger

import (
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/trustbloc/edge-core/pkg/log"
)

// Module is the name of the Watermill module used for logging.
const Module = "watermill"

// Logger wraps the TrustBloc logger and implements the Watermill logger adapter interface.
type Logger struct {
	logger log.Logger
	fields watermill.LogFields
}

// New returns a new Watermill logger adapter.
func New() *Logger {
	return newWMLogger(log.New(Module))
}

func newWMLogger(logger log.Logger) *Logger {
	return &Logger{logger: logger}
}

// Error logs an error.
func (l *Logger) Error(msg string, err error, fields watermill.LogFields) {
	l.logger.Errorf("%s: %s%s", msg, err, l.asString(fields))
}

// Info logs an informational message.
func (l *Logger) Info(msg string, fields watermill.LogFields) {
	// Watermill outputs too many INFO logs, so use the DEBUG log level.
	if level := log.GetLevel(Module); level < log.DEBUG {
		return
	}

	l.logger.Infof("%s%s", msg, l.asString(fields))
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields watermill.LogFields) {
	if level := log.GetLevel(Module); level < log.DEBUG {
		return
	}

	l.logger.Debugf("%s%s", msg, l.asString(fields))
}

// Trace logs a trace message. Note that this implementation uses a debug log for trace.
func (l *Logger) Trace(msg string, fields watermill.LogFields) {
	if level := log.GetLevel(Module); level < log.DEBUG {
		return
	}

	l.logger.Debugf("%s%s", msg, l.asString(fields))
}

// With returns a new logger with the supplied fields so that each log contains these fields.
func (l *Logger) With(fields watermill.LogFields) watermill.LoggerAdapter {
	return &Logger{
		logger: l.logger,
		fields: l.fields.Add(fields),
	}
}

func (l *Logger) asString(additionalFields watermill.LogFields) string {
	if len(l.fields) == 0 && len(additionalFields) == 0 {
		return ""
	}

	var msg string

	for k, v := range l.fields.Add(additionalFields) {
		if msg != "" {
			msg += ", "
		}

		var vStr string
		if stringer, ok := v.(fmt.Stringer); ok {
			vStr = stringer.String()
		} else {
			vStr = fmt.Sprintf("%v", v)
		}

		msg += fmt.Sprintf("%s=%s", k, vStr)
	}

	return " - Fields: " + msg
}
