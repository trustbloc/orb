/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

const internalServerErrorResponse = "Internal Server Error.\n"

type nodeInfoRetriever interface {
	GetNodeInfo(version Version) *NodeInfo
}

// Handler implements the /nodeinfo REST endpoint.
type Handler struct {
	version     Version
	retriever   nodeInfoRetriever
	contentType string
	marshal     func(v interface{}) ([]byte, error)
	logger      logger
}

// NewHandler returns the /nodeinfo REST handler.
// If logger is nil, then a default will be used.
func NewHandler(version Version, retriever nodeInfoRetriever, logger logger) *Handler {
	if logger == nil {
		logger = log.New("nodeinfo")
	}

	return &Handler{
		version:   version,
		retriever: retriever,
		contentType: fmt.Sprintf(`application/json; profile="http://nodeinfo.diaspora.software/ns/schema/%s#"`,
			version),
		marshal: json.Marshal,
		logger:  logger,
	}
}

// Path returns the HTTP REST endpoint for the NodeInfo handler.
func (h *Handler) Path() string {
	return fmt.Sprintf("/nodeinfo/%s", h.version)
}

// Method returns the HTTP REST method for the NodeInfo handler.
func (h *Handler) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the NodeInfo handler.
func (h *Handler) Handler() common.HTTPRequestHandler {
	return h.handle
}

func (h *Handler) handle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", h.contentType)

	nodeInfoBytes, err := h.marshal(h.retriever.GetNodeInfo(h.version))
	if err != nil {
		h.logger.Errorf("Error marshalling node info: %s", err)

		h.writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.writeResponse(w, http.StatusOK, nodeInfoBytes)
}

func (h *Handler) writeResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			h.logger.Warnf("[%s] Unable to write response: %s", h.Path(), err)

			return
		}

		h.logger.Debugf("[%s] Wrote response: %s", h.Path(), body)
	}
}
