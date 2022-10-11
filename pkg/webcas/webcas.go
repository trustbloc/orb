/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	loggerModule = "webcas"

	cidPathVariable = "cid"
)

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// WebCAS represents a WebCAS handler + client for the backing CAS.
type WebCAS struct {
	*resthandler.AuthHandler

	casClient casapi.Client
	logger    *log.Log
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

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// New returns a new WebCAS, which contains a REST handler that implements WebCAS as defined in
// https://trustbloc.github.io/did-method-orb/#webcas.
func New(authCfg *resthandler.Config, s spi.Store, verifier signatureVerifier,
	casClient casapi.Client, tm authTokenManager) *WebCAS {
	h := &WebCAS{
		casClient: casClient,
	}

	h.logger = log.New(loggerModule, log.WithFields(log.WithServiceEndpoint(h.Path())))

	h.AuthHandler = resthandler.NewAuthHandler(authCfg, "/cas/{%s}", http.MethodGet, s, verifier, tm,
		func(actorIRI *url.URL) (bool, error) {
			// TODO: Does the actor need to be authorized? If so, how? A witness needs access to the /cas endpoint
			// but does not need to be part of an actor's 'followers' or 'witnessing' collections (e.g. the case where
			// an offer is sent to a non-system witness).
			// So, for now, let all actors through.

			h.logger.Debug("Authorized actor", log.WithActorIRI(actorIRI))

			return true, nil
		})

	return h
}

func (w *WebCAS) handler(rw http.ResponseWriter, req *http.Request) {
	ok, _, err := w.Authorize(req)
	if err != nil {
		w.logger.Error("Error authorizing request", log.WithRequestURL(req.URL), log.WithError(err))

		rw.WriteHeader(http.StatusInternalServerError)

		if _, errWrite := rw.Write([]byte("Internal Server Error.\n")); errWrite != nil {
			log.WriteResponseBodyError(w.logger, errWrite)
		}

		return
	}

	if !ok {
		w.logger.Info("Request is unauthorized", log.WithRequestURL(req.URL))

		rw.WriteHeader(http.StatusUnauthorized)

		if _, errWrite := rw.Write([]byte("Unauthorized.\n")); errWrite != nil {
			log.WriteResponseBodyError(w.logger, errWrite)
		}

		return
	}

	w.logger.Debug("Request is authorized", log.WithRequestURL(req.URL))

	cid := mux.Vars(req)[cidPathVariable]

	content, err := w.casClient.Read(cid)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			rw.WriteHeader(http.StatusNotFound)

			_, errWrite := fmt.Fprintf(rw, "no content at %s was found: %s", cid, err.Error())
			if errWrite != nil {
				log.WriteResponseBodyError(w.logger, errWrite)
			}

			return
		}

		rw.WriteHeader(http.StatusInternalServerError)

		_, errWrite := fmt.Fprintf(rw, "failure while finding content at %s: %s", cid, err.Error())
		if errWrite != nil {
			log.WriteResponseBodyError(w.logger, errWrite)
		}

		return
	}

	_, err = rw.Write(content)
	if err != nil {
		log.WriteResponseBodyError(w.logger, err)
	}
}
