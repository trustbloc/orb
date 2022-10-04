/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
)

const (
	logURLKey = "log-url"
	endpoint  = "/log"
)

const (
	loggerModule = "log-rest-handler"

	badRequestResponse          = "Bad Request."
	internalServerErrorResponse = "Internal Server Error."
)

// LogConfigurator updates VCT log URL in config store.
type LogConfigurator struct {
	configStore     storage.Store
	logMonitorStore logMonitorStore
	logger          *log.StructuredLog
	marshal         func(interface{}) ([]byte, error)
}

// Path returns the HTTP REST endpoint for the LogConfigurator service.
func (c *LogConfigurator) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the configure VCT URL service.
func (c *LogConfigurator) Method() string {
	return http.MethodPost
}

// Handler returns the HTTP REST handle for the VCT URL Configurator service.
func (c *LogConfigurator) Handler() common.HTTPRequestHandler {
	return c.handle
}

type logMonitorStore interface {
	Activate(logURL string) error
}

// New returns a new LogConfigurator.
func New(cfgStore storage.Store, lmStore logMonitorStore) *LogConfigurator {
	h := &LogConfigurator{
		configStore:     cfgStore,
		logMonitorStore: lmStore,
		logger:          log.NewStructured(loggerModule, log.WithFields(log.WithServiceEndpoint(endpoint))),
		marshal:         json.Marshal,
	}

	return h
}

func (c *LogConfigurator) handle(w http.ResponseWriter, req *http.Request) {
	logURLBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.ReadRequestBodyError(c.logger.Error, err)

		writeResponse(c.logger, w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	logURLStr := string(logURLBytes)

	if logURLStr != "" {
		_, err = url.Parse(logURLStr)
		if err != nil {
			c.logger.Error("Invalid log URL", log.WithError(err))

			writeResponse(c.logger, w, http.StatusBadRequest, []byte(badRequestResponse))

			return
		}
	}

	logConfig := &logConfig{
		URL: logURLStr,
	}

	valueBytes, err := c.marshal(logConfig)
	if err != nil {
		c.logger.Error("Marshal log configuration error", log.WithError(err))

		writeResponse(c.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	err = c.configStore.Put(logURLKey, valueBytes)
	if err != nil {
		c.logger.Error("Error storing log URL", log.WithError(err))

		writeResponse(c.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	c.logger.Debug("Stored log URL", log.WithLogURLString(logURLStr))

	if logURLStr != "" {
		err = c.logMonitorStore.Activate(logURLStr)
		if err != nil {
			c.logger.Error("Error activating log monitoring for log URL", log.WithLogURLString(logURLStr),
				log.WithError(err))

			writeResponse(c.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	writeResponse(c.logger, w, http.StatusOK, nil)
}

func writeResponse(logger *log.StructuredLog, w http.ResponseWriter, status int, body []byte) {
	if len(body) > 0 {
		w.Header().Set("Content-Type", "text/plain")
	}

	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			log.WriteResponseBodyError(logger.Error, err)

			return
		}

		log.WroteResponse(logger.Debug, body)
	}
}

type logConfig struct {
	URL string `json:"url"`
}
