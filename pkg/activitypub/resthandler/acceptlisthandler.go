/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
)

type acceptListMgr interface {
	Update(acceptType string, additions, removals []*url.URL) error
	Get(acceptType string) ([]*url.URL, error)
	GetAll() ([]*spi.AcceptList, error)
}

// AcceptListWriter implements a REST handler to update a service's "accept list".
type AcceptListWriter struct {
	endpoint string
	mgr      acceptListMgr
	marshal  func(v interface{}) ([]byte, error)
	readAll  func(r io.Reader) ([]byte, error)
	logger   *log.Log
}

// NewAcceptListWriter returns a new REST handler to update the "accept list".
func NewAcceptListWriter(cfg *Config, mgr acceptListMgr) *AcceptListWriter {
	endpoint := fmt.Sprintf("%s%s", cfg.BasePath, AcceptListPath)

	return &AcceptListWriter{
		mgr:      mgr,
		endpoint: endpoint,
		marshal:  json.Marshal,
		readAll:  io.ReadAll,
		logger:   log.New(loggerModule, log.WithFields(logfields.WithServiceEndpoint(endpoint))),
	}
}

// Method returns the HTTP method, which is always POST.
func (h *AcceptListWriter) Method() string {
	return http.MethodPost
}

// Path returns the base path of the target URL for this handler.
func (h *AcceptListWriter) Path() string {
	return h.endpoint
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *AcceptListWriter) Handler() common.HTTPRequestHandler {
	return h.handlePost
}

func (h *AcceptListWriter) handlePost(w http.ResponseWriter, req *http.Request) {
	reqBytes, err := h.readAll(req.Body)
	if err != nil {
		h.logger.Error("Error reading request body", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	h.logger.Debug("Got request to update accept list", logfields.WithRequestBody(reqBytes))

	requests, err := unmarshalAndValidateRequest(reqBytes)
	if err != nil {
		h.logger.Info("Error validating request", log.WithError(err))

		writeResponse(h.logger, w, http.StatusBadRequest, []byte(err.Error()))

		return
	}

	for _, req := range requests {
		err = h.mgr.Update(req.acceptType, req.additions, req.deletions)
		if err != nil {
			h.logger.Error("Error updating accept list", log.WithError(err))

			writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

			return
		}
	}

	writeResponse(h.logger, w, http.StatusOK, nil)
}

// AcceptListReader implements a REST handler to read a service's "accept list".
type AcceptListReader struct {
	endpoint string
	mgr      acceptListMgr
	marshal  func(v interface{}) ([]byte, error)
	logger   *log.Log
}

// NewAcceptListReader returns a new REST handler to read a service's "accept list".
func NewAcceptListReader(cfg *Config, mgr acceptListMgr) *AcceptListReader {
	endpoint := fmt.Sprintf("%s%s", cfg.BasePath, AcceptListPath)

	return &AcceptListReader{
		mgr:      mgr,
		endpoint: endpoint,
		logger:   log.New(loggerModule, log.WithFields(logfields.WithServiceEndpoint(endpoint))),
		marshal:  json.Marshal,
	}
}

// Method returns the HTTP method, which is always GET.
func (h *AcceptListReader) Method() string {
	return http.MethodGet
}

// Path returns the base path of the target URL for this handler.
func (h *AcceptListReader) Path() string {
	return h.endpoint
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *AcceptListReader) Handler() common.HTTPRequestHandler {
	return h.handleGet
}

func (h *AcceptListReader) handleGet(w http.ResponseWriter, req *http.Request) {
	acceptType := getTypeParam(req)

	if acceptType == "" {
		h.handleGetAll(w)
	} else {
		h.handleGetByType(acceptType, w)
	}
}

func (h *AcceptListReader) handleGetAll(w http.ResponseWriter) {
	acceptLists, err := h.mgr.GetAll()
	if err != nil {
		h.logger.Error("Error querying accept lists", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	acceptListsBytes, err := h.marshalAcceptLists(acceptLists)
	if err != nil {
		h.logger.Error("Error querying accept list", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	writeResponse(h.logger, w, http.StatusOK, acceptListsBytes)
}

func (h *AcceptListReader) handleGetByType(acceptType string, w http.ResponseWriter) {
	uris, err := h.mgr.Get(acceptType)
	if err != nil {
		h.logger.Error("Error querying accept list", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	acceptListBytes, err := h.marshalAcceptList(acceptType, uris)
	if err != nil {
		h.logger.Error("Error marshalling accept list", log.WithError(err))

		writeResponse(h.logger, w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	writeResponse(h.logger, w, http.StatusOK, acceptListBytes)
}

func writeResponse(logger *log.Log, w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warn("Unable to write response", log.WithError(err))

			return
		}

		logger.Debug("Wrote response", log.WithResponse(body))
	}
}

func (h *AcceptListReader) marshalAcceptList(acceptType string, uris []*url.URL) ([]byte, error) {
	return h.marshal(toAcceptList(acceptType, uris))
}

func (h *AcceptListReader) marshalAcceptLists(acceptLists []*spi.AcceptList) ([]byte, error) {
	lists := make([]*acceptList, len(acceptLists))

	for i, l := range acceptLists {
		lists[i] = toAcceptList(l.Type, l.URL)
	}

	return h.marshal(lists)
}

func toAcceptList(acceptType string, uris []*url.URL) *acceptList {
	list := &acceptList{
		Type: acceptType,
		URLs: make([]string, len(uris)),
	}

	for i, uri := range uris {
		list.URLs[i] = uri.String()
	}

	return list
}

type acceptListRequest struct {
	Type   string   `json:"type"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

type acceptList struct {
	Type string   `json:"type"`
	URLs []string `json:"url"`
}

type request struct {
	acceptType string
	additions  []*url.URL
	deletions  []*url.URL
}

func unmarshalAndValidateRequest(reqBytes []byte) ([]*request, error) {
	var requests []acceptListRequest

	if err := json.Unmarshal(reqBytes, &requests); err != nil {
		return nil, fmt.Errorf("invalid accept list request: %w", err)
	}

	reqs := make([]*request, len(requests))

	for i, r := range requests {
		var err error

		reqs[i], err = newRequest(r)
		if err != nil {
			return nil, fmt.Errorf("invalid accept list request")
		}
	}

	return reqs, nil
}

func newRequest(r acceptListRequest) (*request, error) {
	if r.Type == "" {
		return nil, fmt.Errorf("accept list type is required")
	}

	req := &request{
		acceptType: r.Type,
	}

	var err error

	req.additions, err = parseURIs(r.Add)
	if err != nil {
		return nil, fmt.Errorf("parse URIs for additions: %w", err)
	}

	req.deletions, err = parseURIs(r.Remove)
	if err != nil {
		return nil, fmt.Errorf("parse URIs for deletion: %w", err)
	}

	return req, nil
}

func parseURIs(rawURIs []string) ([]*url.URL, error) {
	if len(rawURIs) == 0 {
		return nil, nil
	}

	uris := make([]*url.URL, len(rawURIs))

	for i, rawURI := range rawURIs {
		uri, err := url.Parse(rawURI)
		if err != nil {
			return nil, fmt.Errorf("invalid URI in accept list: %s", uri)
		}

		uris[i] = uri
	}

	return uris, nil
}
