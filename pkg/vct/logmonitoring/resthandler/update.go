/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

const (
	endpoint = "/log-monitor"
)

const (
	badRequestResponse          = "Bad Request."
	notFoundResponse            = "Not Found"
	internalServerErrorResponse = "Internal Server Error."
)

const loggerModule = "log-monitor-rest-handler"

// UpdateHandler activates VCT log URL in log monitor store.
type UpdateHandler struct {
	logMonitorStore logMonitorStore

	logger    *log.Log
	unmarshal func([]byte, interface{}) error
}

type logMonitorStore interface {
	Activate(logURL string) error
	Deactivate(logURL string) error
	GetActiveLogs() ([]*logmonitor.LogMonitor, error)
	GetInactiveLogs() ([]*logmonitor.LogMonitor, error)
}

// Path returns the HTTP REST endpoint for the UpdateHandler service.
func (a *UpdateHandler) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for activating VCT log for log monitoring service.
func (a *UpdateHandler) Method() string {
	return http.MethodPost
}

// Handler returns the HTTP REST handle for activating VCT log for log monitoring service.
func (a *UpdateHandler) Handler() common.HTTPRequestHandler {
	return a.handle
}

// NewUpdateHandler returns a new UpdateHandler.
func NewUpdateHandler(store logMonitorStore) *UpdateHandler {
	h := &UpdateHandler{
		logMonitorStore: store,
		logger:          log.New(loggerModule, log.WithFields(log.WithServiceEndpoint(endpoint))),
		unmarshal:       json.Unmarshal,
	}

	return h
}

func (a *UpdateHandler) handle(w http.ResponseWriter, req *http.Request) {
	reqBytes, err := io.ReadAll(req.Body)
	if err != nil {
		a.logger.Error("Error reading request body", log.WithError(err))

		writeResponse(a.logger, w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	a.logger.Debug("Got request to activate/deactivate log monitors", log.WithRequestBody(reqBytes))

	request, err := a.unmarshalAndValidateRequest(reqBytes)
	if err != nil {
		a.logger.Info("Error validating request", log.WithError(err))

		writeResponse(a.logger, w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	for _, logURL := range request.Activate {
		err = a.logMonitorStore.Activate(logURL)
		if err != nil {
			a.logger.Error("Error activating log monitoring for log URL", log.WithLogURLString(logURL),
				log.WithError(err))

			writeResponse(a.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	for _, logURL := range request.Deactivate {
		err = a.logMonitorStore.Deactivate(logURL)
		if err != nil {
			a.logger.Error("Error de-activating log monitoring for log URL", log.WithLogURLString(logURL), log.WithError(err))

			writeResponse(a.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	writeResponse(a.logger, w, http.StatusOK, nil)
}

func writeResponse(logger *log.Log, w http.ResponseWriter, status int, body []byte) {
	if len(body) > 0 {
		w.Header().Set("Content-Type", "text/plain")
	}

	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			log.WriteResponseBodyError(logger, err)

			return
		}

		log.WroteResponse(logger, body)
	}
}

func (a *UpdateHandler) unmarshalAndValidateRequest(reqBytes []byte) (*logRequest, error) {
	var request logRequest

	err := a.unmarshal(reqBytes, &request)
	if err != nil {
		return nil, fmt.Errorf("invalid activate/deactivate log request: %w", err)
	}

	err = validateRequest(request)
	if err != nil {
		return nil, fmt.Errorf("invalid activate/deactivate log request: %w", err)
	}

	return &request, nil
}

func validateRequest(r logRequest) error {
	err := validateURIs(r.Activate)
	if err != nil {
		return fmt.Errorf("parse URIs for activate: %w", err)
	}

	err = validateURIs(r.Deactivate)
	if err != nil {
		return fmt.Errorf("parse URIs for deactivate: %w", err)
	}

	return nil
}

func validateURIs(rawURIs []string) error {
	for _, rawURI := range rawURIs {
		uri, err := url.Parse(rawURI)
		if err != nil {
			return fmt.Errorf("invalid URI in the list: %s", uri)
		}
	}

	return nil
}

type logRequest struct {
	Activate   []string `json:"activate"`
	Deactivate []string `json:"deactivate"`
}
