/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

// LogRetriever retrieves the current log URL.
type LogRetriever struct {
	configStore storage.Store
	unmarshal   func([]byte, interface{}) error
}

// Path returns the HTTP REST endpoint for the log retriever.
func (lr *LogRetriever) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the log retriever.
func (lr *LogRetriever) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the log retriever service.
func (lr *LogRetriever) Handler() common.HTTPRequestHandler {
	return lr.handle
}

// NewRetriever returns a new LogRetriever.
func NewRetriever(cfgStore storage.Store) *LogRetriever {
	return &LogRetriever{
		configStore: cfgStore,
		unmarshal:   json.Unmarshal,
	}
}

func (lr *LogRetriever) handle(w http.ResponseWriter, req *http.Request) {
	logBytes, err := lr.configStore.Get(logURLKey)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			logger.Debugf("[%s] log URL not found", endpoint)

			writeResponse(w, http.StatusNotFound, nil)

			return
		}

		logger.Errorf("[%s] Error retrieving log URL: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	var logStr string

	err = lr.unmarshal(logBytes, &logStr)
	if err != nil {
		logger.Errorf("[%s] Error unmarshalling log URL: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Retrieved log URL: %s", endpoint, logStr)

	writeResponse(w, http.StatusOK, []byte(logStr))
}
