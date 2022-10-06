/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wmlogger

import (
	"github.com/ThreeDotsLabs/watermill"
	"go.uber.org/zap"

	"github.com/trustbloc/orb/internal/pkg/log"
)

// Module is the name of the Watermill module used for logging.
const Module = "watermill"

// Logger wraps the TrustBloc logger and implements the Watermill logger adapter interface.
type Logger struct {
	logger logger
	fields watermill.LogFields
}

// New returns a new Watermill logger adapter.
func New() *Logger {
	return newWMLogger(log.New(Module))
}

func newWMLogger(logger logger) *Logger {
	return &Logger{logger: logger}
}

type logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Error(msg string, fields ...zap.Field)
}

// Error logs an error.
func (l *Logger) Error(msg string, err error, fields watermill.LogFields) {
	l.logger.Error(msg, append(l.asZapFields(fields), zap.Error(err))...)
}

// Info logs an informational message.
func (l *Logger) Info(msg string, fields watermill.LogFields) {
	if level := log.GetLevel(Module); level > log.INFO {
		return
	}

	l.logger.Info(msg, l.asZapFields(fields)...)
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields watermill.LogFields) {
	if level := log.GetLevel(Module); level > log.DEBUG {
		return
	}

	l.logger.Debug(msg, l.asZapFields(fields)...)
}

// Trace logs a trace message. Note that this implementation uses a debug log for trace.
func (l *Logger) Trace(msg string, fields watermill.LogFields) {
	if level := log.GetLevel(Module); level > log.DEBUG {
		return
	}

	l.logger.Debug(msg, l.asZapFields(fields)...)
}

// With returns a new logger with the supplied fields so that each log contains these fields.
func (l *Logger) With(fields watermill.LogFields) watermill.LoggerAdapter {
	return &Logger{
		logger: l.logger,
		fields: l.fields.Add(fields),
	}
}

func (l *Logger) asZapFields(additionalFields watermill.LogFields) []zap.Field {
	var fields []zap.Field

	for k, v := range l.fields {
		fields = append(fields, zap.Any(k, v))
	}

	for k, v := range additionalFields {
		fields = append(fields, zap.Any(k, v))
	}

	return fields
}
