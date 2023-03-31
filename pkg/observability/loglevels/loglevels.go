/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package loglevels

import (
	"io"
	"net/http"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

var logger = log.New("loglevels")

const (
	logLevelsPath               = "/loglevels"
	internalServerErrorResponse = "Internal Server Error.\n"
	badRequestResponse          = "Bad Request.\n"
)

// WriteHandler is a REST handler that updates the default log level and/or log levels on specified modules.
type WriteHandler struct {
	logger  *log.Log
	readAll func(r io.Reader) ([]byte, error)
}

// NewWriteHandler returns a new log levels POST handler.
func NewWriteHandler() *WriteHandler {
	return &WriteHandler{
		logger:  logger.With(logfields.WithServiceEndpoint(logLevelsPath)),
		readAll: io.ReadAll,
	}
}

// Method returns the HTTP method.
func (h *WriteHandler) Method() string {
	return http.MethodPost
}

// Path returns the HTTP path.
func (h *WriteHandler) Path() string {
	return logLevelsPath
}

// Handler returns the HTTP handler.
func (h *WriteHandler) Handler() common.HTTPRequestHandler {
	return h.handlePost
}

func (h *WriteHandler) handlePost(w http.ResponseWriter, req *http.Request) {
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

// ReadHandler is a REST handler that returns the logging spec in the format "module1=level1:module2=level2:defaultLevel".
type ReadHandler struct {
	logger *log.Log
}

// NewReadHandler returns a new log levels GET handler.
func NewReadHandler() *ReadHandler {
	return &ReadHandler{
		logger: logger.With(logfields.WithServiceEndpoint(logLevelsPath)),
	}
}

// Method returns the HTTP methods.
func (h *ReadHandler) Method() string {
	return http.MethodGet
}

// Path returns the HTTP path.
func (h *ReadHandler) Path() string {
	return logLevelsPath
}

// Handler returns the HTTP handler.
func (h *ReadHandler) Handler() common.HTTPRequestHandler {
	return h.handleGet
}

func (h *ReadHandler) handleGet(w http.ResponseWriter, _ *http.Request) {
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
