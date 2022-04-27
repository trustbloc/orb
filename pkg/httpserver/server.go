/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	logger = log.New("httpserver")
	// BuildVersion contains the version of the Orb build.
	//nolint:gochecknoglobals
	BuildVersion string
)

const (
	healthCheckEndpoint = "/healthcheck"
	success             = "success"
)

// Server implements an HTTP server.
type Server struct {
	httpServer *http.Server
	started    uint32
	certFile   string
	keyFile    string
	pubSub     pubSub
	vct        vct
	db         db
}

type pubSub interface {
	IsConnected() error
}

type vct interface {
	HealthCheck() error
}

type db interface {
	Ping() error
}

// New returns a new HTTP server.
func New(url, certFile, keyFile string, serverIdleTimeout time.Duration, pubSub pubSub, vct vct, db db,
	handlers ...common.HTTPHandler) *Server {
	s := &Server{
		certFile: certFile,
		keyFile:  keyFile,
		pubSub:   pubSub,
		vct:      vct,
		db:       db,
	}

	router := mux.NewRouter()

	for _, handler := range handlers {
		logger.Infof("Registering handler for [%s]", handler.Path())
		router.HandleFunc(handler.Path(), handler.Handler()).
			Methods(handler.Method()).
			Queries(params(handler)...)
	}

	// add health check endpoint
	router.HandleFunc(healthCheckEndpoint, s.healthCheckHandler).Methods(http.MethodGet)

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
			logger.Errorf("http2 server error %s", errType)
		},
	}

	httpServ := &http.Server{
		Addr:        url,
		Handler:     h2c.NewHandler(handler, http2Server),
		IdleTimeout: serverIdleTimeout,
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
		return fmt.Errorf("cannot stop HTTP server since it hasn't been started")
	}

	return s.httpServer.Shutdown(ctx)
}

type healthCheckResp struct {
	MQStatus    string    `json:"mqStatus,omitempty"`
	VCTStatus   string    `json:"vctStatus,omitempty"`
	DBStatus    string    `json:"dbStatus,omitempty"`
	CurrentTime time.Time `json:"currentTime,omitempty"`
	Version     string    `json:"version,omitempty"`
}

func (s *Server) healthCheckHandler(rw http.ResponseWriter, r *http.Request) { //nolint:gocyclo,cyclop
	mqStatus := ""
	vctStatus := ""
	dbStatus := ""

	if s.pubSub != nil {
		mqStatus = success

		if err := s.pubSub.IsConnected(); err != nil {
			mqStatus = err.Error()
		}
	}

	if s.vct != nil {
		vctStatus = success

		if err := s.vct.HealthCheck(); err != nil {
			vctStatus = err.Error()
		}
	}

	if s.db != nil {
		dbStatus = success

		if err := s.db.Ping(); err != nil {
			dbStatus = err.Error()
		}
	}

	if mqStatus != success || vctStatus != success || dbStatus != success {
		rw.WriteHeader(http.StatusServiceUnavailable)
	} else {
		rw.WriteHeader(http.StatusOK)
	}

	err := json.NewEncoder(rw).Encode(&healthCheckResp{
		MQStatus:    mqStatus,
		VCTStatus:   vctStatus,
		DBStatus:    dbStatus,
		CurrentTime: time.Now(),
		Version:     BuildVersion,
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
