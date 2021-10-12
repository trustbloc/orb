/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

var logger = log.New("handler-with-auth-restapi")

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// HandlerWrapper authenticates request before calling handler.
type HandlerWrapper struct {
	*resthandler.AuthHandler

	handleRequest common.HTTPRequestHandler

	resolver common.HTTPHandler
}

// NewHandlerWrapper returns a new 'authenticated' handler. It verifies both tokens and signatures before proceeding.
func NewHandlerWrapper(handler common.HTTPHandler, authCfg *resthandler.Config, s spi.Store, verifier signatureVerifier) *HandlerWrapper { //nolint:lll
	ah := &HandlerWrapper{
		resolver:      handler,
		handleRequest: handler.Handler(),
	}

	ah.AuthHandler = resthandler.NewAuthHandler(authCfg, handler.Path(), handler.Method(), s, verifier,
		func(actorIRI *url.URL) (bool, error) {
			logger.Debugf("[%s] Authorized actor [%s]", ah.Path(), actorIRI)

			return true, nil
		})

	return ah
}

// Path returns the context path.
func (o *HandlerWrapper) Path() string {
	return o.resolver.Path()
}

// Method returns the HTTP method.
func (o *HandlerWrapper) Method() string {
	return o.resolver.Method()
}

// Handler returns the handler function.
func (o *HandlerWrapper) Handler() common.HTTPRequestHandler {
	return o.handler
}

func (o *HandlerWrapper) handler(rw http.ResponseWriter, req *http.Request) {
	ok, _, err := o.Authorize(req)
	if err != nil {
		logger.Errorf("Error authorizing request[%s]: %s", req.URL, err)

		rw.WriteHeader(http.StatusInternalServerError)

		if _, errWrite := rw.Write([]byte("Internal Server Error.\n")); errWrite != nil {
			logger.Errorf("Unable to write response: %s", errWrite)
		}

		return
	}

	if !ok {
		logger.Infof("Request[%s] is unauthorized", req.URL)

		rw.WriteHeader(http.StatusUnauthorized)

		if _, errWrite := rw.Write([]byte("Unauthorized.\n")); errWrite != nil {
			logger.Errorf("Unable to write response: %s", errWrite)
		}

		return
	}

	logger.Debugf("Request[%s] is authorized", req.URL)

	o.handleRequest(rw, req)
}