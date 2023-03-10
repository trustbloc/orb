/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"io"
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

const (
	// LogLevelFlagName is the flag name used for setting the default log level.
	LogLevelFlagName = "log-level"
	// LogLevelEnvKey is the env var name used for setting the default log level.
	LogLevelEnvKey = "LOG_LEVEL"
	// LogLevelFlagShorthand is the shorthand flag name used for setting the default log level.
	LogLevelFlagShorthand = "l"
	// LogLevelPrefixFlagUsage is the usage text for the log level flag.
	LogLevelPrefixFlagUsage = "Sets logging levels for individual modules as well as the default level. `+" +
		"`The format of the string is as follows: module1=level1:module2=level2:defaultLevel. `+" +
		"`Supported levels are: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		"`Example: metrics=INFO:nodeinfo=WARNING:activitypub_store=INFO:DEBUG. `+" +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + LogLevelEnvKey
)

const (
	logSpecErrorMsg = `Invalid log spec. It needs to be in the following format: "ModuleName1=Level1` +
		`:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel"
Valid log levels: critical,error,warn,info,debug
Error: %s`

	logSpecPath                 = "/loglevels"
	internalServerErrorResponse = "Internal Server Error.\n"
	badRequestResponse          = "Bad Request.\n"
)

// setLogLevels sets the log levels for individual modules as well as the default level.
func setLogLevels(logger *log.Log, logSpec string) {
	if err := log.SetSpec(logSpec); err != nil {
		logger.Warn(logSpecErrorMsg, log.WithError(err))

		log.SetDefaultLevel(log.INFO)
	} else {
		logger.Info("Successfully set log levels", logfields.WithLogSpec(log.GetSpec()))
	}
}

// logSpecWriter is a REST handler that updates the default log level and/or log levels on specified modules.
type logSpecWriter struct {
	logger  *log.Log
	readAll func(r io.Reader) ([]byte, error)
}

func newLogSpecWriter() *logSpecWriter {
	return &logSpecWriter{
		logger:  logger.With(logfields.WithServiceEndpoint(logSpecPath)),
		readAll: io.ReadAll,
	}
}

func (h *logSpecWriter) Method() string {
	return http.MethodPost
}

func (h *logSpecWriter) Path() string {
	return logSpecPath
}

func (h *logSpecWriter) Handler() common.HTTPRequestHandler {
	return h.handlePost
}

func (h *logSpecWriter) handlePost(w http.ResponseWriter, req *http.Request) {
	reqBytes, err := h.readAll(req.Body)
	if err != nil {
		h.logger.Error("Error reading request body", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.logger.Debug("Got request to update log levels", logfields.WithRequestBody(reqBytes))

	request := string(reqBytes)

	err = log.SetSpec(request)
	if err != nil {
		h.logger.Warn("Set logging spec error", logfields.WithLogSpec(request), log.WithError(err))

		writeResponse(h.logger, w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	h.logger.Info("Successfully updated log levels", logfields.WithLogSpec(log.GetSpec()))

	writeResponse(h.logger, w, http.StatusOK, nil)
}

// logSpecReader is a REST handler that returns the logging spec in the format "module1=level1:module2=level2:defaultLevel".
type logSpecReader struct {
	logger *log.Log
}

func newLogSpecReader() *logSpecReader {
	return &logSpecReader{
		logger: logger.With(logfields.WithServiceEndpoint(logSpecPath)),
	}
}

func (h *logSpecReader) Method() string {
	return http.MethodGet
}

func (h *logSpecReader) Path() string {
	return logSpecPath
}

func (h *logSpecReader) Handler() common.HTTPRequestHandler {
	return h.handleGet
}

func (h *logSpecReader) handleGet(w http.ResponseWriter, _ *http.Request) {
	writeResponse(h.logger, w, http.StatusOK, []byte(log.GetSpec()))
}

func writeResponse(logger *log.Log, w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warn("Unable to write response", log.WithError(err))

			return
		}

		logger.Debug("Wrote response", log.WithResponse(body))
	}
}
