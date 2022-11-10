/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/trustbloc/orb/internal/pkg/log"
)

var (
	logger = log.New("httpserver")

	// BuildVersion contains the version of the Orb build.
	BuildVersion string
)

// Server implements an HTTP server.
type Server struct {
	httpServer *http.Server
	started    uint32
	certFile   string
	keyFile    string
}

// New returns a new HTTP server.
func New(url, certFile, keyFile string, serverIdleTimeout, serverReadHeaderTimeout time.Duration,
	handlers ...common.HTTPHandler) *Server {
	s := &Server{
		certFile: certFile,
		keyFile:  keyFile,
	}

	router := mux.NewRouter()

	for _, handler := range handlers {
		logger.Info("Registering handler", log.WithServiceEndpoint(handler.Path()))

		router.HandleFunc(handler.Path(), handler.Handler()).
			Methods(handler.Method()).
			Queries(params(handler)...)
	}

	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{
				http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
			},
			AllowedHeaders: []string{"*"},
		},
	).Handler(router)

	http2Server := &http2.Server{
		IdleTimeout: serverIdleTimeout,
		CountError: func(errType string) {
			logger.Error("HTTP2 server error", log.WithError(errors.New(errType)))
		},
	}

	httpServ := &http.Server{
		Addr:              url,
		Handler:           h2c.NewHandler(handler, http2Server),
		IdleTimeout:       serverIdleTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
	}

	s.httpServer = httpServ

	return s
}

// Start starts the HTTP server in a separate Go routine.
func (s *Server) Start() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return fmt.Errorf("server already started")
	}

	go func() {
		logger.Info("Listening for requests", log.WithAddress(s.httpServer.Addr))

		var err error
		if s.keyFile != "" && s.certFile != "" {
			err = s.httpServer.ListenAndServeTLS(s.certFile, s.keyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("Failed to start server on [%s]: %s", s.httpServer.Addr, err))
		}

		atomic.StoreUint32(&s.started, 0)

		logger.Info("Server has stopped")
	}()

	return nil
}

// Stop stops the REST service.
func (s *Server) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapUint32(&s.started, 1, 0) {
		return fmt.Errorf("cannot stop HTTP server since it hasn't been started")
	}

	return s.httpServer.Shutdown(ctx)
}

type paramHolder interface {
	Params() map[string]string
}

func params(handler common.HTTPHandler) []string {
	var queries []string

	if p, ok := handler.(paramHolder); ok {
		for name, value := range p.Params() {
			queries = append(queries, name, value)
		}
	}

	return queries
}
