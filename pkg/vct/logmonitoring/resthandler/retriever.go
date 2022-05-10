/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

// RetrieveHandler retrieves the current log URL.
type RetrieveHandler struct {
	logMonitorStore logMonitorStore
	marshal         func(interface{}) ([]byte, error)
}

// Path returns the HTTP REST endpoint for the log retriever.
func (r *RetrieveHandler) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the log retriever.
func (r *RetrieveHandler) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the log retriever service.
func (r *RetrieveHandler) Handler() common.HTTPRequestHandler {
	return r.handle
}

// NewRetriever returns a new RetrieveHandler.
func NewRetriever(store logMonitorStore) *RetrieveHandler {
	return &RetrieveHandler{
		logMonitorStore: store,
		marshal:         json.Marshal,
	}
}

func (r *RetrieveHandler) handle(w http.ResponseWriter, req *http.Request) {
	status := "active"

	queryValue := req.URL.Query()["status"]
	if len(queryValue) > 0 {
		status = queryValue[0]
	}

	logs, err := r.getLogs(status)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Debugf("[%s] no %s logs found", status, endpoint)

			writeResponse(w, http.StatusNotFound, []byte(notFoundResponse))

			return
		}

		logger.Errorf("[%s] Error retrieving logs: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	retBytes, err := r.marshal(logs)
	if err != nil {
		logger.Errorf("[%s] Marshal logs error: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Retrieved %s logs", endpoint, status)

	writeResponse(w, http.StatusOK, retBytes)
}

func (r *RetrieveHandler) getLogs(status string) (*logResponse, error) {
	var response *logResponse

	switch status {
	case "active":
		logs, err := r.logMonitorStore.GetActiveLogs()
		if err != nil {
			return nil, err
		}

		response = &logResponse{Active: logs}

	case "inactive":
		logs, err := r.logMonitorStore.GetInactiveLogs()
		if err != nil {
			return nil, err
		}

		response = &logResponse{Inactive: logs}

	default:
		return nil, fmt.Errorf("status '%s' is not supported", status)
	}

	return response, nil
}

type logResponse struct {
	Active   []*logmonitor.LogMonitor `json:"active,omitempty"`
	Inactive []*logmonitor.LogMonitor `json:"inactive,omitempty"`
}
