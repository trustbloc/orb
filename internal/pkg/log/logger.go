/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Level defines a log level for logging messages.
type Level int

// String returns string representation of given log level.
func (l Level) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARNING:
		return "WARN"
	case ERROR:
		return "ERROR"
	case PANIC:
		return "PANIC"
	case FATAL:
		return "FATAL"
	default:
		return fmt.Sprintf("Level(%d)", l)
	}
}

// ParseLevel returns the level from the given string.
func ParseLevel(level string) (Level, error) {
	switch level {
	case "DEBUG", "debug":
		return DEBUG, nil
	case "INFO", "info":
		return INFO, nil
	case "WARN", "warn", "WARNING", "warning":
		return WARNING, nil
	case "ERROR", "error":
		return ERROR, nil
	case "PANIC", "panic":
		return PANIC, nil
	case "FATAL", "fatal":
		return FATAL, nil
	default:
		return ERROR, errors.New("logger: invalid log level")
	}
}

// Log levels.
const (
	DEBUG   = Level(zapcore.DebugLevel)
	INFO    = Level(zapcore.InfoLevel)
	WARNING = Level(zapcore.WarnLevel)
	ERROR   = Level(zapcore.ErrorLevel)
	PANIC   = Level(zapcore.PanicLevel)
	FATAL   = Level(zapcore.FatalLevel)

	minLogLevel = DEBUG
)

// Logger - Standard logger interface.
type Logger interface {
	// Fatalf is critical fatal logging, should possibly be followed by a call to os.Exit(1)
	Fatalf(msg string, args ...interface{})

	// Panicf is critical logging, should possibly be followed by panic
	Panicf(msg string, args ...interface{})

	// Debugf is for logging verbose messages
	Debugf(msg string, args ...interface{})

	// Infof for logging general logging messages
	Infof(msg string, args ...interface{})

	// Warnf is for logging messages about possible issues
	Warnf(msg string, args ...interface{})

	// Errorf is for logging errors
	Errorf(msg string, args ...interface{})

	// isEnabledFor returns true if the logger is enabled for the given level.
	IsEnabled(level Level) bool
}

const (
	defaultLevel      = INFO
	defaultModuleName = ""
	callerSkip        = 1
)

var levels = newModuleLevels() //nolint:gochecknoglobals

// Log is an implementation of Logger interface.
type Log struct {
	instance *zap.SugaredLogger
	module   string
	stdOut   zapcore.WriteSyncer
	stdErr   zapcore.WriteSyncer
}

// Option is a logger option.
type Option func(l *Log)

// WithStdOut sets the output for logs of type DEBUG, INFO, and WARN.
func WithStdOut(stdOut zapcore.WriteSyncer) Option {
	return func(l *Log) {
		l.stdOut = stdOut
	}
}

// WithStdErr sets the output for logs of type ERROR, PANIC, and FATAL.
func WithStdErr(stdErr zapcore.WriteSyncer) Option {
	return func(l *Log) {
		l.stdErr = stdErr
	}
}

// New creates and returns a Logger implementation based on given module name.
// note: the underlying logger instance is lazy initialized on first use.
// To use your own logger implementation provide logger provider in 'Initialize()' before logging any line.
// If 'Initialize()' is not called before logging any line then default logging implementation will be used.
func New(module string, opts ...Option) *Log {
	l := &Log{
		module: module,
		stdOut: os.Stdout,
		stdErr: os.Stderr,
	}

	for _, opt := range opts {
		opt(l)
	}

	l.initialize()

	return l
}

func (l *Log) initialize() {
	encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeName: func(moduleName string, encoder zapcore.PrimitiveArrayEncoder) {
			encoder.AppendString(fmt.Sprintf("[%s]", moduleName))
		},
	})

	core := zapcore.NewTee(
		zapcore.NewCore(encoder, zapcore.Lock(l.stdErr),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl >= zapcore.ErrorLevel && levels.isEnabled(l.module, Level(lvl))
			}),
		),
		zapcore.NewCore(encoder, zapcore.Lock(l.stdOut),
			zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
				return lvl < zapcore.ErrorLevel && levels.isEnabled(l.module, Level(lvl))
			}),
		),
	)

	l.instance = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(callerSkip)).Named(l.module).Sugar()
}

// Fatalf log a templated message, then calls os.Exit.
func (l *Log) Fatalf(msg string, args ...interface{}) {
	l.instance.Fatalf(msg, args...)
}

// Panicf log a templated message, then panics.
func (l *Log) Panicf(msg string, args ...interface{}) {
	l.instance.Panicf(msg, args...)
}

// Debugf logs a templated message.
func (l *Log) Debugf(msg string, args ...interface{}) {
	l.instance.Debugf(msg, args...)
}

// Infof logs a templated message.
func (l *Log) Infof(msg string, args ...interface{}) {
	l.instance.Infof(msg, args...)
}

// Warnf logs a templated message.
func (l *Log) Warnf(msg string, args ...interface{}) {
	l.instance.Warnf(msg, args...)
}

// Errorf logs a templated message.
func (l *Log) Errorf(msg string, args ...interface{}) {
	l.instance.Errorf(msg, args...)
}

// IsEnabled returns true if given log level is enabled.
func (l *Log) IsEnabled(level Level) bool {
	return levels.isEnabled(l.module, level)
}

// SetLevel sets the log level for given module and level.
func SetLevel(module string, level Level) {
	levels.Set(module, level)
}

// SetDefaultLevel sets the default log level.
func SetDefaultLevel(level Level) {
	levels.SetDefault(level)
}

// GetLevel returns the log level for the given module.
func GetLevel(module string) Level {
	return levels.Get(module)
}

// SetSpec sets the log levels for individual modules as well as the default log level.
// The format of the spec is as follows:
//
//	  module1=level1:module2=level2:module3=level3:defaultLevel
//
// Valid log levels are: critical, error, warning, info, debug
//
// Example:
//    module1=error:module2=debug:module3=warning:info
//
func SetSpec(spec string) error {
	logLevelByModule := strings.Split(spec, ":")

	defaultLogLevel := minLogLevel - 1

	var moduleLevelPairs []moduleLevelPair

	for _, logLevelByModulePart := range logLevelByModule {
		if strings.Contains(logLevelByModulePart, "=") {
			moduleAndLevelPair := strings.Split(logLevelByModulePart, "=")

			logLevel, err := ParseLevel(moduleAndLevelPair[1])
			if err != nil {
				return err
			}

			moduleLevelPairs = append(moduleLevelPairs,
				moduleLevelPair{moduleAndLevelPair[0], logLevel})
		} else {
			if defaultLogLevel >= minLogLevel {
				return errors.New("multiple default values found")
			}

			level, err := ParseLevel(logLevelByModulePart)
			if err != nil {
				return err
			}

			defaultLogLevel = level
		}
	}

	if defaultLogLevel >= minLogLevel {
		levels.Set("", defaultLogLevel)
	} else {
		levels.Set("", INFO)
	}

	for _, moduleLevelPair := range moduleLevelPairs {
		levels.Set(moduleLevelPair.module, moduleLevelPair.logLevel)
	}

	return nil
}

// GetSpec returns the log spec which specifies the log level of each individual module. The spec is
// in the following format:
//
//	  module1=level1:module2=level2:module3=level3:defaultLevel
//
// Example:
//    module1=error:module2=debug:module3=warning:info
//
func GetSpec() string {
	var spec string

	var defaultDebugLevel string

	for module, level := range getAllLevels() {
		if module == "" {
			defaultDebugLevel = level.String()
		} else {
			spec += fmt.Sprintf("%s=%s:", module, level.String())
		}
	}

	return spec + defaultDebugLevel
}

func getAllLevels() map[string]Level {
	metadataLevels := levels.All()

	// Convert to the Level type in this package
	levels := make(map[string]Level)
	for module, logLevel := range metadataLevels {
		levels[module] = logLevel
	}

	return levels
}

type moduleLevelPair struct {
	module   string
	logLevel Level
}

func newModuleLevels() *moduleLevels {
	return &moduleLevels{levels: make(map[string]Level)}
}

// moduleLevels maintains log levels based on modules.
type moduleLevels struct {
	levels  map[string]Level
	rwmutex sync.RWMutex
}

// Get returns the log level for given module and level.
func (l *moduleLevels) Get(module string) Level {
	l.rwmutex.RLock()
	defer l.rwmutex.RUnlock()

	level, exists := l.levels[module]
	if !exists {
		level, exists = l.levels[defaultModuleName]
		// no configuration exists, default to info
		if !exists {
			return defaultLevel
		}
	}

	return level
}

// All returns all set log levels.
func (l *moduleLevels) All() map[string]Level {
	l.rwmutex.RLock()
	levels := l.levels
	l.rwmutex.RUnlock()

	levelsCopy := make(map[string]Level)

	for module, logLevel := range levels {
		levelsCopy[module] = logLevel
	}

	return levelsCopy
}

func (l *moduleLevels) Set(module string, level Level) {
	l.rwmutex.Lock()
	l.levels[module] = level
	l.rwmutex.Unlock()
}

func (l *moduleLevels) SetDefault(level Level) {
	l.Set(defaultModuleName, level)
}

// isEnabled will return true if logging is enabled for given module and level.
func (l *moduleLevels) isEnabled(module string, level Level) bool {
	return level >= l.Get(module)
}
