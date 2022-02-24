/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
)

const endpoint = "/policy"

const (
	badRequestResponse          = "Bad Request."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("policy-rest-handler")

// PolicyConfigurator updates witness policy in config store.
type PolicyConfigurator struct {
	configStore storage.Store
	marshal     func(interface{}) ([]byte, error)
}

// Path returns the HTTP REST endpoint for the PolicyConfigurator service.
func (pc *PolicyConfigurator) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the configure policy service.
func (pc *PolicyConfigurator) Method() string {
	return http.MethodPost
}

// Handler returns the HTTP REST handle for the PolicyConfigurator service.
func (pc *PolicyConfigurator) Handler() common.HTTPRequestHandler {
	return pc.handle
}

// New returns a new PolicyConfigurator.
func New(cfgStore storage.Store) *PolicyConfigurator {
	h := &PolicyConfigurator{
		configStore: cfgStore,
		marshal:     json.Marshal,
	}

	return h
}

func (pc *PolicyConfigurator) handle(w http.ResponseWriter, req *http.Request) {
	policyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf("[%s] Error reading request body: %s", endpoint, err)

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	policyStr := string(policyBytes)

	_, err = config.Parse(policyStr)
	if err != nil {
		logger.Errorf("[%s] Invalid witness policy: %s", endpoint, err)

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	valueBytes, err := pc.marshal(policyStr)
	if err != nil {
		logger.Errorf("[%s] Marshal witness policy error: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	err = pc.configStore.Put(policy.WitnessPolicyKey, valueBytes)
	if err != nil {
		logger.Errorf("[%s] Error storing witness policy: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Stored witness policy %s", endpoint, string(policyBytes))

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
