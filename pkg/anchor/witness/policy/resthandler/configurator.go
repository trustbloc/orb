/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"io"
	"net/http"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
)

const endpoint = "/policy"

const (
	badRequestResponse          = "Bad Request."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("policy-rest-handler", log.WithFields(log.WithServiceEndpoint(endpoint)))

type policyStore interface {
	PutPolicy(policyStr string) error
	GetPolicy() (string, error)
}

// PolicyConfigurator updates witness policy in config store.
type PolicyConfigurator struct {
	store policyStore
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
func New(store policyStore) *PolicyConfigurator {
	h := &PolicyConfigurator{
		store: store,
	}

	return h
}

func (pc *PolicyConfigurator) handle(w http.ResponseWriter, req *http.Request) {
	policyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Error("Error reading request body", log.WithError(err))

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	policyStr := string(policyBytes)

	_, err = config.Parse(policyStr)
	if err != nil {
		logger.Error("Invalid witness policy", log.WithError(err), log.WithWitnessPolicy(policyStr))

		writeResponse(w, http.StatusBadRequest, []byte(badRequestResponse))

		return
	}

	err = pc.store.PutPolicy(policyStr)
	if err != nil {
		logger.Error("Error storing witness policy", log.WithError(err))

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debug("Stored witness policy", log.WithWitnessPolicy(policyStr))

	writeResponse(w, http.StatusOK, nil)
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
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
