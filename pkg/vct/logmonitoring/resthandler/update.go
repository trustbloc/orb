/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

const (
	endpoint = "/log-monitor"
)

const (
	badRequestResponse          = "Bad Request."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("log-monitor-rest-handler")

// UpdateHandler activates VCT log URL in log monitor store.
type UpdateHandler struct {
	logMonitorStore logMonitorStore

	unmarshal func([]byte, interface{}) error
}

type logMonitorStore interface {
	Activate(logURL string) error
	Deactivate(logURL string) error
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
		unmarshal:       json.Unmarshal,
	}

	return h
}

func (a *UpdateHandler) handle(w http.ResponseWriter, req *http.Request) {
	reqBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[%s] Error reading request body: %s", endpoint, err)

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	logger.Debugf("[%s] Got request to activate/deactivate log monitors: %s", endpoint, reqBytes)

	request, err := a.unmarshalAndValidateRequest(reqBytes)
	if err != nil {
		logger.Infof("[%s] Error validating request: %s", endpoint, err)

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	for _, logURL := range request.Activate {
		err = a.logMonitorStore.Activate(logURL)
		if err != nil {
			logger.Errorf("[%s] Error while activating log monitoring for log URL[%s]: %s", endpoint, logURL, err)

			writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	for _, logURL := range request.Deactivate {
		err = a.logMonitorStore.Deactivate(logURL)
		if err != nil {
			logger.Errorf("[%s] Error while de-activating log monitoring for log URL[%s]: %s", endpoint, logURL, err)

			writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	writeResponse(w, http.StatusOK, nil)
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
	if len(body) > 0 {
		w.Header().Set("Content-Type", "text/plain")
	}

	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warnf("[%s] Unable to write response: %s", endpoint, err)

			return
		}

		logger.Debugf("[%s] Wrote response: %s", endpoint, body)
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
