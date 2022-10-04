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
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/trustbloc/orb/internal/pkg/log"
	vct2 "github.com/trustbloc/orb/pkg/vct"
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
	unknown             = "unknown error"
	notConnected        = "not connected"
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
	keyManager keyManager
}

type pubSub interface {
	IsConnected() bool
}

type vct interface {
	HealthCheck() error
}

type db interface {
	Ping() error
}

type keyManager interface {
	HealthCheck() error
}

// New returns a new HTTP server.
func New(url, certFile, keyFile string, serverIdleTimeout time.Duration, pubSub pubSub, vct vct, db db,
	keyManager keyManager, handlers ...common.HTTPHandler) *Server {
	s := &Server{
		certFile:   certFile,
		keyFile:    keyFile,
		pubSub:     pubSub,
		vct:        vct,
		db:         db,
		keyManager: keyManager,
	}

	router := mux.NewRouter()

	for _, handler := range handlers {
		logger.Info("Registering handler", log.WithServiceEndpoint(handler.Path()))

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
			logger.Error("HTTP2 server error", log.WithError(errors.New(errType)))
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

type healthCheckResp struct {
	MQStatus    string    `json:"mqStatus,omitempty"`
	VCTStatus   string    `json:"vctStatus,omitempty"`
	DBStatus    string    `json:"dbStatus,omitempty"`
	KMSStatus   string    `json:"kmsStatus,omitempty"`
	CurrentTime time.Time `json:"currentTime,omitempty"`
	Version     string    `json:"version,omitempty"`
}

func (s *Server) healthCheckHandler(rw http.ResponseWriter, r *http.Request) {
	var mqStatus, vctStatus, dbStatus, kmsStatus string

	returnStatusServiceUnavailable := false

	unavailable, mqStatus := s.mqHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, vctStatus = s.vctHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, dbStatus = s.dbHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, kmsStatus = s.kmsHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	status := http.StatusOK

	if returnStatusServiceUnavailable {
		status = http.StatusServiceUnavailable
	}

	hc := &healthCheckResp{
		MQStatus:    mqStatus,
		VCTStatus:   vctStatus,
		DBStatus:    dbStatus,
		KMSStatus:   kmsStatus,
		CurrentTime: time.Now(),
		Version:     BuildVersion,
	}

	hcBytes, err := json.Marshal(hc)
	if err != nil {
		logger.Error("Healthcheck marshal error", log.WithError(err))

		return
	}

	logger.Debug("Health check returning response", log.WithHTTPStatus(status), log.WithResponse(hcBytes))

	rw.WriteHeader(status)

	_, err = rw.Write(hcBytes)
	if err != nil {
		logger.Error("Healthcheck response failure", log.WithError(err))
	}
}

func (s *Server) mqHealthCheck() (bool, string) {
	if s.pubSub == nil {
		return false, ""
	}

	if s.pubSub.IsConnected() {
		return false, success
	}

	return true, notConnected
}

func (s *Server) vctHealthCheck() (bool, string) {
	if s.vct == nil {
		return false, ""
	}

	err := s.vct.HealthCheck()
	if err == nil {
		return false, success
	}

	if errors.Is(err, vct2.ErrLogEndpointNotConfigured) || errors.Is(err, vct2.ErrDisabled) {
		// It's not an error if VCT is disabled or no log endpoint was configured.
		// Return the message so that the client knows the status of VCT.
		return false, err.Error()
	}

	return true, toStatus(err)
}

func (s *Server) dbHealthCheck() (bool, string) {
	if s.db == nil {
		return false, ""
	}

	err := s.db.Ping()
	if err == nil {
		return false, success
	}

	return true, toStatus(err)
}

func (s *Server) kmsHealthCheck() (bool, string) {
	if s.keyManager == nil {
		return false, ""
	}

	err := s.keyManager.HealthCheck()
	if err == nil {
		return false, success
	}

	return true, toStatus(err)
}

func toStatus(err error) string {
	if err.Error() != "" {
		return err.Error()
	}

	return unknown
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
