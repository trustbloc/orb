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

// PolicyRetriever retrieves the current witness policy.
type PolicyRetriever struct {
	store     policyStore
	unmarshal func([]byte, interface{}) error
}

// Path returns the HTTP REST endpoint for the policy retriever.
func (pc *PolicyRetriever) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the policy retriever.
func (pc *PolicyRetriever) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the PolicyRetriever service.
func (pc *PolicyRetriever) Handler() common.HTTPRequestHandler {
	return pc.handle
}

// NewRetriever returns a new PolicyRetriever.
func NewRetriever(store policyStore) *PolicyRetriever {
	return &PolicyRetriever{
		store:     store,
		unmarshal: json.Unmarshal,
	}
}

func (pc *PolicyRetriever) handle(w http.ResponseWriter, req *http.Request) {
	policyStr, err := pc.store.GetPolicy()
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			logger.Debugf("[%s] Witness policy not found", endpoint)

			writeResponse(w, http.StatusNotFound, nil)

			return
		}

		logger.Errorf("[%s] Error retrieving witness policy: %s", endpoint, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Retrieved witness policy %s", endpoint, policyStr)

	writeResponse(w, http.StatusOK, []byte(policyStr))
}
