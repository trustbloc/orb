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
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

const (
	logURLKey = "log-url"
	endpoint  = "/log"
)

const (
	badRequestResponse          = "Bad Request."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("log-rest-handler")

// LogConfigurator updates VCT log URL in config store.
type LogConfigurator struct {
	configStore     storage.Store
	logMonitorStore logMonitorStore
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
		marshal:         json.Marshal,
	}

	return h
}

func (c *LogConfigurator) handle(w http.ResponseWriter, req *http.Request) {
	logURLBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[%s] Error reading request body: %s", endpoint, err)

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	logURLStr := string(logURLBytes)

	if logURLStr != "" {
		_, err = url.Parse(logURLStr)
		if err != nil {
			logger.Errorf("[%s] Invalid log URL: %s", endpoint, err)

			writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

			return
		}
	}

	logConfig := &logConfig{
		URL: logURLStr,
	}

	valueBytes, err := c.marshal(logConfig)
	if err != nil {
		logger.Errorf("[%s] Marshal log configuration error: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	err = c.configStore.Put(logURLKey, valueBytes)
	if err != nil {
		logger.Errorf("[%s] Error storing log URL: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Stored log URL %s", endpoint, string(logURLBytes))

	if logURLStr != "" {
		err = c.logMonitorStore.Activate(logURLStr)
		if err != nil {
			logger.Errorf("[%s] Error activating log monitoring for log URL: %s", endpoint, err)

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

type logConfig struct {
	URL string `json:"url"`
}
