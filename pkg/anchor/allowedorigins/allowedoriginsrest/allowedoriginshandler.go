/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginsrest

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

var logger = log.New("allowed-origins")

const (
	allowedOriginsPath          = "/allowedorigins"
	internalServerErrorResponse = "Internal Server Error.\n"
)

type allowedOriginsMgr interface {
	Update(additions, removals []*url.URL) error
	Get() ([]*url.URL, error)
}

// Writer implements a REST handler to update the "allowed origins".
type Writer struct {
	mgr     allowedOriginsMgr
	marshal func(v interface{}) ([]byte, error)
	readAll func(r io.Reader) ([]byte, error)
}

// NewWriter returns a new REST handler to update the "allowed origins".
func NewWriter(mgr allowedOriginsMgr) *Writer {
	return &Writer{
		mgr:     mgr,
		marshal: json.Marshal,
		readAll: ioutil.ReadAll,
	}
}

// Method returns the HTTP method, which is always POST.
func (h *Writer) Method() string {
	return http.MethodPost
}

// Path returns the base path of the target URL for this handler.
func (h *Writer) Path() string {
	return allowedOriginsPath
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *Writer) Handler() common.HTTPRequestHandler {
	return h.handlePost
}

func (h *Writer) handlePost(w http.ResponseWriter, req *http.Request) {
	reqBytes, err := h.readAll(req.Body)
	if err != nil {
		logger.Errorf("[%s] Error reading request body: %s", allowedOriginsPath, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	logger.Debugf("[%s] Got request to update allowed origins: %s", allowedOriginsPath, reqBytes)

	request, err := unmarshalAndValidateRequest(reqBytes)
	if err != nil {
		logger.Infof("[%s] Error validating request: %s", allowedOriginsPath, err)

		writeResponse(w, http.StatusBadRequest, []byte(err.Error()))

		return
	}

	err = h.mgr.Update(request.additions, request.deletions)
	if err != nil {
		logger.Errorf("[%s] Error updating allowed origins: %s", allowedOriginsPath, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	writeResponse(w, http.StatusOK, nil)
}

// Reader implements a REST handler to read the "allowed origins".
type Reader struct {
	mgr     allowedOriginsMgr
	marshal func(v interface{}) ([]byte, error)
}

// NewReader returns a new REST handler to read a service's "allowed origins".
func NewReader(mgr allowedOriginsMgr) *Reader {
	return &Reader{
		mgr:     mgr,
		marshal: json.Marshal,
	}
}

// Method returns the HTTP method, which is always GET.
func (h *Reader) Method() string {
	return http.MethodGet
}

// Path returns the base path of the target URL for this handler.
func (h *Reader) Path() string {
	return allowedOriginsPath
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *Reader) Handler() common.HTTPRequestHandler {
	return h.handleGet
}

func (h *Reader) handleGet(w http.ResponseWriter, _ *http.Request) {
	allowedOrigins, err := h.mgr.Get()
	if err != nil {
		logger.Errorf("[%s] Error querying allowed originss: %s", allowedOriginsPath, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	allowedOriginsBytes, err := h.marshalAllowedOrigins(allowedOrigins)
	if err != nil {
		logger.Errorf("[%s] Error querying allowed origins: %s", allowedOriginsPath, err)

		writeResponse(w, http.StatusInternalServerError, []byte(internalServerErrorResponse))

		return
	}

	writeResponse(w, http.StatusOK, allowedOriginsBytes)
}

func writeResponse(w http.ResponseWriter, status int, body []byte) {
	w.WriteHeader(status)

	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			logger.Warnf("[%s] Unable to write response: %s", allowedOriginsPath, err)

			return
		}

		logger.Debugf("[%s] Wrote response: %s", allowedOriginsPath, body)
	}
}

func (h *Reader) marshalAllowedOrigins(allowedOrigins []*url.URL) ([]byte, error) {
	return h.marshal(vocab.NewURLCollectionProperty(allowedOrigins...))
}

type allowedOriginsRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

type request struct {
	additions []*url.URL
	deletions []*url.URL
}

func unmarshalAndValidateRequest(reqBytes []byte) (*request, error) {
	request := &allowedOriginsRequest{}

	if err := json.Unmarshal(reqBytes, request); err != nil {
		return nil, fmt.Errorf("invalid allowed origins request: %w", err)
	}

	req, err := newRequest(request)
	if err != nil {
		return nil, fmt.Errorf("invalid allowed origins request")
	}

	return req, nil
}

func newRequest(r *allowedOriginsRequest) (*request, error) {
	req := &request{}

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
			return nil, fmt.Errorf("invalid URI in allowed origins: %s", uri)
		}

		uris[i] = uri
	}

	return uris, nil
}
