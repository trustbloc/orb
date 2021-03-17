/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
)

var logger = logrus.New()

const healthCheckEndpoint = "/healthcheck"

// Server implements an HTTP server.
type Server struct {
	httpServer *http.Server
	started    uint32
	certFile   string
	keyFile    string
}

// New returns a new HTTP server.
func New(url, certFile, keyFile, token string, handlers ...common.HTTPHandler) *Server {
	router := mux.NewRouter()

	if token != "" {
		router.Use(authorizationMiddleware(token))
	}

	for _, handler := range handlers {
		logger.Infof("Registering handler for [%s]", handler.Path())
		router.HandleFunc(handler.Path(), handler.Handler()).
			Methods(handler.Method()).
			Queries(params(handler)...)
	}

	// add health check endpoint
	router.HandleFunc(healthCheckEndpoint, healthCheckHandler).Methods(http.MethodGet)

	handler := cors.New(
		cors.Options{
			AllowedMethods: []string{
				http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
			},
			AllowedHeaders: []string{"*"},
		},
	).Handler(router)

	return &Server{
		httpServer: &http.Server{
			Addr:    url,
			Handler: handler,
		},
		certFile: certFile,
		keyFile:  keyFile,
	}
}

// Start starts the HTTP server in a separate Go routine.
func (s *Server) Start() error {
	if !atomic.CompareAndSwapUint32(&s.started, 0, 1) {
		return errors.New("server already started")
	}

	go func() {
		logger.Infof("listening for requests on [%s]", s.httpServer.Addr)

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
		logger.Infof("server has stopped")
	}()

	return nil
}

// Stop stops the REST service.
func (s *Server) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapUint32(&s.started, 1, 0) {
		return errors.New("cannot stop HTTP server since it hasn't been started")
	}

	return s.httpServer.Shutdown(ctx)
}

func validateAuthorizationBearerToken(w http.ResponseWriter, r *http.Request, token string) bool {
	actHdr := r.Header.Get("Authorization")
	expHdr := "Bearer " + token

	if subtle.ConstantTimeCompare([]byte(actHdr), []byte(expHdr)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorised.\n")) // nolint:gosec,errcheck

		return false
	}

	return true
}

func authorizationMiddleware(token string) mux.MiddlewareFunc {
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validateAuthorizationBearerToken(w, r, token) {
				next.ServeHTTP(w, r)
			}
		})
	}

	return middleware
}

type healthCheckResp struct {
	Status      string    `json:"status"`
	CurrentTime time.Time `json:"currentTime"`
}

func healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusOK)

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		Status:      "success",
		CurrentTime: time.Now(),
	})
	if err != nil {
		logger.Errorf("healthcheck response failure, %s", err)
	}
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
