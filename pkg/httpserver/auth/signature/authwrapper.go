/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"net/http"
	"net/url"

	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

const loggerModule = "handler-with-auth-restapi"

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

// HandlerWrapper authenticates request before calling handler.
type HandlerWrapper struct {
	*resthandler.AuthHandler

	handleRequest common.HTTPRequestHandler
	resolver      common.HTTPHandler
	logger        *log.Log
}

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

// NewHandlerWrapper returns a new 'authenticated' handler. It verifies both tokens and signatures before proceeding.
func NewHandlerWrapper(handler common.HTTPHandler, authCfg *resthandler.Config, s spi.Store,
	verifier signatureVerifier, tm authTokenManager) *HandlerWrapper {
	logger := log.New(loggerModule, log.WithFields(log.WithServiceEndpoint(handler.Path())))

	ah := &HandlerWrapper{
		resolver:      handler,
		handleRequest: handler.Handler(),
		logger:        logger,
	}

	ah.AuthHandler = resthandler.NewAuthHandler(authCfg, handler.Path(), handler.Method(), s, verifier, tm,
		func(actorIRI *url.URL) (bool, error) {
			logger.Debug("Authorized actor", log.WithActorIRI(actorIRI))

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
		o.logger.Error("Error authorizing request", log.WithRequestURL(req.URL), log.WithError(err))

		rw.WriteHeader(http.StatusInternalServerError)

		if _, errWrite := rw.Write([]byte("Internal Server Error.\n")); errWrite != nil {
			log.WriteResponseBodyError(o.logger, errWrite)
		}

		return
	}

	if !ok {
		o.logger.Info("Request is unauthorized", log.WithRequestURL(req.URL))

		rw.WriteHeader(http.StatusUnauthorized)

		if _, errWrite := rw.Write([]byte("Unauthorized.\n")); errWrite != nil {
			log.WriteResponseBodyError(o.logger, errWrite)
		}

		return
	}

	o.logger.Debug("Request is authorized", log.WithRequestURL(req.URL))

	o.handleRequest(rw, req)
}
