/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type mockWriter struct {
	*bytes.Buffer
}

func (m *mockWriter) Sync() error {
	return nil
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: bytes.NewBuffer(nil)}
}

// TestDefaultLogger tests default logging feature when no custom logging provider is supplied via 'Initialize()' call.
func TestDefaultLogger(t *testing.T) {
	const module = "sample-module"

	t.Run("Default level", func(t *testing.T) {
		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debugf("Sample debug log. Some number [%d]", 123)
		logger.Infof("Sample info log. Some number [%d]", 123)
		logger.Warnf("Sample warn log")
		logger.Errorf("Sample error log")

		require.Panics(t, func() {
			logger.Panicf("Sample panic log")
		})

		require.NotContains(t, stdOut.Buffer.String(), "DEBUG")
		require.Contains(t, stdOut.Buffer.String(), "INFO")
		require.Contains(t, stdOut.Buffer.String(), "WARN")
		require.NotContains(t, stdOut.Buffer.String(), "PANIC")
		require.NotContains(t, stdOut.Buffer.String(), "FATAL")

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})

	t.Run("DEBUG", func(t *testing.T) {
		SetLevel(module, DEBUG)

		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debugf("Sample debug log. Some number [%d]", 123)
		logger.Infof("Sample info log. Some number [%d]", 123)
		logger.Warnf("Sample warn log")
		logger.Errorf("Sample error log")

		require.Panics(t, func() {
			logger.Panicf("Sample panic log")
		})

		require.Contains(t, stdOut.Buffer.String(), "DEBUG")
		require.Contains(t, stdOut.Buffer.String(), "INFO")
		require.Contains(t, stdOut.Buffer.String(), "WARN")
		require.NotContains(t, stdOut.Buffer.String(), "PANIC")
		require.NotContains(t, stdOut.Buffer.String(), "FATAL")

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})

	t.Run("ERROR", func(t *testing.T) {
		SetLevel(module, ERROR)

		stdOut := newMockWriter()
		stdErr := newMockWriter()

		logger := New(module, WithStdOut(stdOut), WithStdErr(stdErr))

		logger.Debugf("Sample debug log. Some number [%d]", 123)
		logger.Infof("Sample info log. Some number [%d]", 123)
		logger.Warnf("Sample warn log")
		logger.Errorf("Sample error log")

		require.Panics(t, func() {
			logger.Panicf("Sample panic log")
		})

		require.Empty(t, stdOut.Buffer.String())

		require.NotContains(t, stdErr.Buffer.String(), "DEBUG")
		require.NotContains(t, stdErr.Buffer.String(), "INFO")
		require.NotContains(t, stdErr.Buffer.String(), "WARN")
		require.Contains(t, stdErr.Buffer.String(), "ERROR")
		require.Contains(t, stdErr.Buffer.String(), "PANIC")
	})
}

// TestAllLevels tests logging level behaviour
// logging levels can be set per modules, if not set then it will default to 'INFO'.
func TestAllLevels(t *testing.T) {
	module := "sample-module-critical"

	SetLevel(module, FATAL)
	require.Equal(t, FATAL, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL}, []Level{PANIC, ERROR, WARNING, INFO, DEBUG})

	SetLevel(module, PANIC)
	require.Equal(t, PANIC, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC}, []Level{ERROR, WARNING, INFO, DEBUG})

	module = "sample-module-error"
	SetLevel(module, ERROR)
	require.Equal(t, ERROR, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR}, []Level{WARNING, INFO, DEBUG})

	module = "sample-module-warning"
	SetLevel(module, WARNING)
	require.Equal(t, WARNING, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING}, []Level{INFO, DEBUG})

	module = "sample-module-info"
	SetLevel(module, INFO)
	require.Equal(t, INFO, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING, INFO}, []Level{DEBUG})

	module = "sample-module-debug"
	SetLevel(module, DEBUG)
	require.Equal(t, DEBUG, GetLevel(module))
	verifyLevels(t, module, []Level{FATAL, PANIC, ERROR, WARNING, INFO, DEBUG}, []Level{})
}

func TestGetAllLevels(t *testing.T) {
	sampleModuleCritical := "sample-module-critical"
	SetLevel(sampleModuleCritical, PANIC)

	sampleModuleWarning := "sample-module-warning"
	SetLevel(sampleModuleWarning, WARNING)

	allLogLevels := getAllLevels()
	require.Equal(t, PANIC, allLogLevels[sampleModuleCritical])
	require.Equal(t, WARNING, allLogLevels[sampleModuleWarning])
}

// TestLogLevel testing 'LogLevel()' used for parsing log levels from strings.
func TestLogLevel(t *testing.T) {
	verifyLevelsNoError := func(expected Level, levels ...string) {
		for _, level := range levels {
			actual, err := ParseLevel(level)
			require.NoError(t, err, "not supposed to fail while parsing level string [%s]", level)
			require.Equal(t, expected, actual)
		}
	}

	verifyLevelsNoError(FATAL, "fatal", "FATAL")
	verifyLevelsNoError(PANIC, "panic", "PANIC")
	verifyLevelsNoError(ERROR, "error", "ERROR")
	verifyLevelsNoError(WARNING, "warn", "WARN", "warning", "WARNING")
	verifyLevelsNoError(DEBUG, "debug", "DEBUG")
	verifyLevelsNoError(INFO, "info", "INFO")
}

// TestParseLevelError testing 'LogLevel()' used for parsing log levels from strings.
func TestParseLevelError(t *testing.T) {
	verifyLevelError := func(levels ...string) {
		for _, level := range levels {
			_, err := ParseLevel(level)
			require.Error(t, err, "not supposed to succeed while parsing level string [%s]", level)
		}
	}

	verifyLevelError("", "D", "DE BUG", ".")
}

func TestParseString(t *testing.T) {
	require.Equal(t, "FATAL", FATAL.String())
	require.Equal(t, "PANIC", PANIC.String())
	require.Equal(t, "ERROR", ERROR.String())
	require.Equal(t, "WARN", WARNING.String())
	require.Equal(t, "INFO", INFO.String())
	require.Equal(t, "DEBUG", DEBUG.String())
}

func TestSetSpecLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=panic:error"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, PANIC, GetLevel("module2"))
		require.Equal(t, ERROR, GetLevel(""))
	})

	t.Run("Successfully set logging levels - no default", func(t *testing.T) {
		resetLoggingLevels()

		require.NoError(t, SetSpec("module1=debug:module2=panic"))

		require.Equal(t, DEBUG, GetLevel("module1"))
		require.Equal(t, PANIC, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("Module1=InvalidLogLevel")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log level")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})

	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		err := SetSpec("debug:debug")
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple default values found")

		// Log levels should remain at the default setting of "info"
		require.Equal(t, INFO, GetLevel("module1"))
		require.Equal(t, INFO, GetLevel("module2"))
		require.Equal(t, INFO, GetLevel(""))
	})
}

func TestLogSpecGet(t *testing.T) {
	resetLoggingLevels()

	spec := GetSpec()

	t.Logf("Got spec: %s", spec)

	require.Contains(t, spec, "module1=INFO")
	require.Contains(t, spec, "module2=INFO")
	require.Contains(t, spec, ":INFO")
}

func TestLogLevels(t *testing.T) {
	mlevel := newModuleLevels()

	mlevel.Set("module-xyz-info", INFO)
	mlevel.Set("module-xyz-debug", DEBUG)
	mlevel.Set("module-xyz-error", ERROR)
	mlevel.Set("module-xyz-warning", WARNING)
	mlevel.Set("module-xyz-panic", PANIC)

	// Run info level checks
	require.True(t, mlevel.isEnabled("module-xyz-info", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-info", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-info", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-info", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-info", DEBUG))

	// Run debug level checks
	require.True(t, mlevel.isEnabled("module-xyz-debug", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-debug", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-debug", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-debug", INFO))
	require.True(t, mlevel.isEnabled("module-xyz-debug", DEBUG))

	// Run warning level checks
	require.True(t, mlevel.isEnabled("module-xyz-warning", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-warning", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-warning", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-warning", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-warning", DEBUG))

	// Run error level checks
	require.True(t, mlevel.isEnabled("module-xyz-error", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-error", ERROR))
	require.False(t, mlevel.isEnabled("module-xyz-error", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-error", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-error", DEBUG))

	// Run error panic checks
	require.True(t, mlevel.isEnabled("module-xyz-panic", PANIC))
	require.False(t, mlevel.isEnabled("module-xyz-panic", ERROR))
	require.False(t, mlevel.isEnabled("module-xyz-panic", WARNING))
	require.False(t, mlevel.isEnabled("module-xyz-panic", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-panic", DEBUG))

	// Run default log level check --> which is info level
	require.True(t, mlevel.isEnabled("module-xyz-random-module", PANIC))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", ERROR))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", WARNING))
	require.True(t, mlevel.isEnabled("module-xyz-random-module", INFO))
	require.False(t, mlevel.isEnabled("module-xyz-random-module", DEBUG))
}

func TestStructuredLogger(t *testing.T) {
	const module = "test_module"

	u1 := parseURL(t, "https://example1.com")
	u2 := parseURL(t, "https://example2.com")
	u3 := parseURL(t, "https://example3.com")

	t.Run("console error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := NewStructured(module,
			WithStdErr(stdErr),
			WithFields(WithServiceName("myservice")),
		)

		logger.Error("Sample error", WithError(errors.New("some error")))

		require.Contains(t, stdErr.Buffer.String(), `Sample error	{"service": "myservice", "error": "some error"}`)
	})

	t.Run("json error", func(t *testing.T) {
		stdErr := newMockWriter()

		logger := NewStructured(module,
			WithStdErr(stdErr), WithEncoding(JSON),
			WithFields(WithServiceName("myservice")),
		)

		logger.Error("Sample error", WithError(errors.New("some error")))

		var l logData
		require.NoError(t, json.Unmarshal(stdErr.Bytes(), &l))

		require.Equal(t, "myservice", l.Service)
		require.Equal(t, "test_module", l.Logger)
		require.Equal(t, "Sample error", l.Msg)
		require.Contains(t, l.Caller, "log/logger_test.go")
		require.Equal(t, "some error", l.Error)
		require.Equal(t, "error", l.Level)
	})

	t.Run("json fields 1", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := NewStructured(module, WithStdOut(stdOut), WithEncoding(JSON))

		logger.Info("Some message",
			WithMessageID("msg1"), WithPayload([]byte(`{"field":"value"}`)),
			WithActorIRI(u1), WithActivityID(u2), WithActivityType("Create"),
			WithServiceIRI(parseURL(t, u2.String())), WithServiceName("service1"),
			WithServiceEndpoint("/services/service1"),
			WithSize(1234), WithExpiration(12*time.Second),
			WithTargetIRI(u1), WithQueue("queue1"),
			WithHTTPStatus(http.StatusNotFound), WithParameter("param1"),
			WithReferenceType("followers"), WithURI(u2),
			WithSenderURL(u1), WithAnchorURI(u3), WithAnchorEventURI(u3),
			WithAcceptListType("follow"),
			WithAcceptListAdditions(u1, u3),
			WithAcceptListDeletions(u1),
			WithRequestURL(u1), WithRequestBody([]byte(`request body`)), WithResponse([]byte(`response body`)),
			WithRequestHeaders(map[string][]string{"key1": {"v1", "v2"}, "key2": {"v3"}}),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, `msg1`, l.MessageID)
		require.Equal(t, `{"field":"value"}`, l.Payload)
		require.Equal(t, u1.String(), l.ActorID)
		require.Equal(t, u2.String(), l.ActivityID)
		require.Equal(t, `Create`, l.ActivityType)
		require.Equal(t, `service1`, l.Service)
		require.Equal(t, `/services/service1`, l.ServiceEndpoint)
		require.Equal(t, u2.String(), l.ServiceIri)
		require.Equal(t, 1234, l.Size)
		require.Equal(t, `12s`, l.Expiration)
		require.Equal(t, u1.String(), l.Target)
		require.Equal(t, `queue1`, l.Queue)
		require.Equal(t, 404, l.HTTPStatus)
		require.Equal(t, `param1`, l.Parameter)
		require.Equal(t, `followers`, l.ReferenceType)
		require.Equal(t, u2.String(), l.URI)
		require.Equal(t, u3.String(), l.AnchorURI)
		require.Equal(t, u3.String(), l.AnchorEventURI)
		require.Equal(t, `follow`, l.AcceptListType)
		require.Equal(t, []string{u1.String(), u3.String()}, l.AcceptListAdditions)
		require.Equal(t, []string{u1.String()}, l.AcceptListDeletions)
		require.Equal(t, u1.String(), l.RequestURL)
		require.Equal(t, `request body`, l.RequestBody)
		require.Equal(t, `response body`, l.Response)
		require.Equal(t, map[string][]string{"key1": {"v1", "v2"}, "key2": {"v3"}}, l.RequestHeaders)
	})

	t.Run("json fields 2", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := NewStructured(module, WithStdOut(stdOut), WithEncoding(JSON))

		logger.Info("Some message",
			WithActorID(u1.String()), WithTarget(u2.String()),
			WithConfig(&mockConfig{Field1: "value1", Field2: 1234}),
			WithRequestURLString(u1.String()),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, u1.String(), l.ActorID)
		require.Equal(t, u2.String(), l.Target)
		require.Equal(t, `{"Field1":"value1","Field2":1234}`, l.Config)
		require.Equal(t, u1.String(), l.RequestURL)
	})

	t.Run("marshal error", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := NewStructured(module, WithStdOut(stdOut), WithEncoding(JSON))

		logger.Info("Some message", WithConfig(func() {}))

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, `marshal json: json: unsupported type: func()`, l.Error)
	})
}

func resetLoggingLevels() {
	SetLevel("module1", INFO)
	SetLevel("module2", INFO)
	SetDefaultLevel(INFO)
}

func verifyLevels(t *testing.T, module string, enabled, disabled []Level) {
	t.Helper()

	for _, level := range enabled {
		require.True(t, levels.isEnabled(module, level),
			"expected level [%s] to be enabled for module [%s]", level, module)
	}

	for _, level := range disabled {
		require.False(t, levels.isEnabled(module, level),
			"expected level [%s] to be disabled for module [%s]", level, module)
	}
}

type mockConfig struct {
	Field1 string
	Field2 int
}

type logData struct {
	Level  string `json:"level"`
	Time   string `json:"time"`
	Logger string `json:"logger"`
	Caller string `json:"caller"`
	Msg    string `json:"msg"`
	Error  string `json:"error"`

	MessageID           string              `json:"message-id"`
	Payload             string              `json:"payload"`
	ActorID             string              `json:"actor-id"`
	ActivityID          string              `json:"activity-id"`
	ActivityType        string              `json:"activity-type"`
	ServiceIri          string              `json:"service-iri"`
	Service             string              `json:"service"`
	ServiceEndpoint     string              `json:"service-endpoint"`
	Size                int                 `json:"size"`
	Expiration          string              `json:"expiration"`
	Target              string              `json:"target"`
	Queue               string              `json:"queue"`
	HTTPStatus          int                 `json:"http-status"`
	Parameter           string              `json:"parameter"`
	ReferenceType       string              `json:"reference-type"`
	URI                 string              `json:"uri"`
	Sender              string              `json:"sender"`
	AnchorURI           string              `json:"anchor-uri"`
	AnchorEventURI      string              `json:"anchor-event-uri"`
	Config              string              `json:"config"`
	AcceptListType      string              `json:"accept-list-type"`
	AcceptListAdditions []string            `json:"accept-list-additions"`
	AcceptListDeletions []string            `json:"accept-list-deletions"`
	RequestURL          string              `json:"request-url"`
	RequestHeaders      map[string][]string `json:"request-headers"`
	RequestBody         string              `json:"request-body"`
	Response            string              `json:"response"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}
