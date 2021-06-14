/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/didanchor"
)

const (
	suffixPathVariable = "suffix"
	endpoint           = "/origin/{" + suffixPathVariable + "}"

	notFoundResponse            = "Not Found."
	internalServerErrorResponse = "Internal Server Error."
)

var logger = log.New("did-anchor-handler")

// DidOriginHandler retrieves the latest anchor origin for this did (suffix).
type DidOriginHandler struct {
	*resthandler.AuthHandler

	protocolClientProvider protocol.ClientProvider
	didAnchors             didAnchorProvider
	anchorGraph            anchorGraphProvider
}

// didAnchorProvider interface provides access to latest anchor for suffix.
type didAnchorProvider interface {
	Get(suffix string) (string, error)
}

// anchorGraphProvider provides access to anchor graph.
type anchorGraphProvider interface {
	GetDidAnchors(cid, suffix string) ([]graph.Anchor, error)
}

// Path returns the HTTP REST endpoint for the service.
func (h *DidOriginHandler) Path() string {
	return endpoint
}

// Method returns the HTTP REST method for the service.
func (h *DidOriginHandler) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handle for the service.
func (h *DidOriginHandler) Handler() common.HTTPRequestHandler {
	return h.handle
}

// New returns a new DidOriginHandler.
func New(didAnchors didAnchorProvider, pcp protocol.ClientProvider, ag anchorGraphProvider) *DidOriginHandler {
	h := &DidOriginHandler{
		didAnchors:             didAnchors,
		protocolClientProvider: pcp,
		anchorGraph:            ag,
	}

	return h
}

func (h *DidOriginHandler) handle(w http.ResponseWriter, req *http.Request) {
	suffix := mux.Vars(req)[suffixPathVariable]

	anchor, err := h.didAnchors.Get(suffix)
	if err != nil {
		if errors.Is(err, didanchor.ErrDataNotFound) {
			writeResponse(w, http.StatusNotFound, []byte(notFoundResponse))

			return
		}

		logger.Errorf("[%s] Error retrieving anchor for suffix[%s]: %s", endpoint, suffix, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	anchors, err := h.anchorGraph.GetDidAnchors(anchor, suffix)
	if err != nil {
		logger.Errorf("[%s] Error retrieving anchors for suffix[%s] starting from anchor[%s]: %s",
			endpoint, suffix, anchor, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] got %d anchors for suffix[%s]", endpoint, len(anchors), suffix)

	anchorOrigin, err := h.getLatestAnchorOriginFromAnchors(anchors, suffix)
	if err != nil {
		logger.Errorf(err.Error())

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Infof("[%s] latest anchor origin for suffix[%s]: %s", endpoint, suffix, anchorOrigin)

	writeResponse(w, http.StatusOK, []byte(anchorOrigin))
}

func (h *DidOriginHandler) getLatestAnchorOriginFromAnchors(anchors []graph.Anchor, suffix string) (string, error) {
	for i := len(anchors) - 1; i >= 0; i-- {
		a := anchors[i]

		logger.Debugf("[%s] processing anchor[%s] for suffix[%s]", endpoint, a.CID, suffix)

		op, err := h.getAnchoredOperation(a.CID, a.Info, suffix)
		if err != nil {
			return "", fmt.Errorf(
				"[%s] Error retrieving anchored operation from Sidetree batch for suffix[%s] and anchor[%s]: %w",
				endpoint, suffix, a.CID, err)
		}

		if op.Type == operation.TypeCreate || op.Type == operation.TypeRecover {
			anchorOrigin, ok := op.AnchorOrigin.(string)
			if !ok {
				return "", fmt.Errorf("[%s] Unexpected interface '%T' for anchor origin object",
					endpoint, op.AnchorOrigin)
			}

			return anchorOrigin, nil
		}
	}

	// we should never reach this point if anchor graph is healthy
	return "", fmt.Errorf("[%s] Unable to resolve latest anchor origin from anchor graph for suffix[%s]",
		endpoint, suffix)
}

func (h *DidOriginHandler) getAnchoredOperation(anchor string, info *verifiable.Credential, suffix string) (*operation.AnchoredOperation, error) { //nolint:lll
	anchorPayload, err := util.GetAnchorSubject(info)
	if err != nil {
		return nil, fmt.Errorf("failed to extract anchor payload from anchor[%s]: %w", anchor, err)
	}

	pc, err := h.protocolClientProvider.ForNamespace(anchorPayload.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get client versions for namespace [%s]: %w", anchorPayload.Namespace, err)
	}

	v, err := pc.Get(anchorPayload.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get client version for version[%d]: %w", anchorPayload.Version, err)
	}

	ad := &util.AnchorData{OperationCount: anchorPayload.OperationCount, CoreIndexFileURI: anchorPayload.CoreIndex}

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:      uint64(info.Issued.Unix()),
		AnchorString:         ad.GetAnchorString(),
		Namespace:            anchorPayload.Namespace,
		ProtocolGenesisTime:  anchorPayload.Version,
		CanonicalReference:   anchor,
		EquivalentReferences: []string{anchor},
	}

	logger.Debugf("[%s] processing anchor[%s], core index[%s]", endpoint, anchor, anchorPayload.CoreIndex)

	txnOps, err := v.OperationProvider().GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve operations for anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	return getSuffixOp(txnOps, suffix)
}

func getSuffixOp(txnOps []*operation.AnchoredOperation, suffix string) (*operation.AnchoredOperation, error) {
	for _, op := range txnOps {
		if op.UniqueSuffix == suffix {
			return op, nil
		}
	}

	return nil, fmt.Errorf("suffix[%s] not found in anchored operations", suffix)
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warnf("[%s] Unable to write response: %s", endpoint, err)

			return
		}

		logger.Debugf("[%s] Wrote response: %s", endpoint, body)
	}
}
