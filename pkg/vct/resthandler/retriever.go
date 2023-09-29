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
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

// LogRetriever retrieves the current log URL.
type LogRetriever struct {
	configStore storage.Store
	logger      *log.Log
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
		logger:      log.New(loggerModule, log.WithFields(logfields.WithServiceEndpoint(endpoint))),
		unmarshal:   json.Unmarshal,
	}
}

func (lr *LogRetriever) handle(w http.ResponseWriter, req *http.Request) {
	logConfigBytes, err := lr.configStore.Get(logURLKey)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			lr.logger.Debug("Log URL not found")

			writeResponse(lr.logger, w, http.StatusNotFound, nil)

			return
		}

		lr.logger.Error("Error retrieving log URL", log.WithError(err))

		writeResponse(lr.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logConfig := &logConfig{}

	err = lr.unmarshal(logConfigBytes, &logConfig)
	if err != nil {
		lr.logger.Error("Error unmarshalling log configuration", log.WithError(err))

		writeResponse(lr.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	lr.logger.Debug("Retrieved log URL", logfields.WithLogURLString(logConfig.URL))

	writeResponse(lr.logger, w, http.StatusOK, []byte(logConfig.URL))
}
