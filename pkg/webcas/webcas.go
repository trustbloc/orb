/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	cas "github.com/trustbloc/orb/pkg/store/cas"
)

const cidPathVariable = "cid"

type logger interface {
	Errorf(msg string, args ...interface{})
}

// WebCAS represents a WebCAS handler + client for the backing CAS.
type WebCAS struct {
	casClient casapi.Client
	logger    logger
}

// Path returns the HTTP REST endpoint for the WebCAS service.
func (w *WebCAS) Path() string {
	return fmt.Sprintf("/cas/{%s}", cidPathVariable)
}

// Method returns the HTTP REST method for the WebCAS service.
func (w *WebCAS) Method() string {
	return http.MethodGet
}

// Handler returns the HTTP REST handler for the WebCAS service.
func (w *WebCAS) Handler() common.HTTPRequestHandler {
	return w.handler
}

// New returns a new WebCAS, which contains a REST handler that implements WebCAS as defined in
// https://trustbloc.github.io/did-method-orb/#webcas.
func New(casClient casapi.Client) *WebCAS {
	return &WebCAS{casClient: casClient, logger: log.New("webcas")}
}

func (w *WebCAS) handler(rw http.ResponseWriter, req *http.Request) {
	cid := mux.Vars(req)[cidPathVariable]

	content, err := w.casClient.Read(cid)
	if err != nil {
		if errors.Is(err, cas.ErrContentNotFound) {
			rw.WriteHeader(http.StatusNotFound)

			_, errWrite := rw.Write([]byte(fmt.Sprintf("no content at %s was found: %s", cid, err.Error())))
			if errWrite != nil {
				w.logger.Errorf("failed to write error response. CAS error that led to this: %s. "+
					"Response write error: %s", err.Error(), errWrite.Error())
			}

			return
		}

		rw.WriteHeader(http.StatusInternalServerError)

		_, errWrite := rw.Write([]byte(fmt.Sprintf("failure while finding content at %s: %s", cid, err.Error())))
		if errWrite != nil {
			w.logger.Errorf("failed to write error response. CAS error that led to this: %s. "+
				"Response write error: %s", err.Error(), errWrite.Error())
		}

		return
	}

	_, err = rw.Write(content)
	if err != nil {
		w.logger.Errorf("failed to write success response: %s", err.Error())
	}
}
