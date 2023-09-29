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
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-svc-go/pkg/restapi/common"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

const (
	defaultServerIdleTimeout       = 20 * time.Second
	defaultServerReadHeaderTimeout = 20 * time.Second
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

type options struct {
	handlers                []common.HTTPHandler
	certFile                string
	keyFile                 string
	serverIdleTimeout       time.Duration
	serverReadHeaderTimeout time.Duration
	tracingEnabled          bool
	tracingServiceName      string
}

// Opt is an HTTP server option.
type Opt func(*options)

// WithHandlers adds HTTP request handlers.
func WithHandlers(handlers ...common.HTTPHandler) Opt {
	return func(options *options) {
		options.handlers = append(options.handlers, handlers...)
	}
}

// WithCertFile sets the TLS certificate file.
func WithCertFile(value string) Opt {
	return func(options *options) {
		options.certFile = value
	}
}

// WithKeyFile sets the TLS key file.
func WithKeyFile(value string) Opt {
	return func(options *options) {
		options.keyFile = value
	}
}

// WithServerIdleTimeout sets the idle timeout.
func WithServerIdleTimeout(value time.Duration) Opt {
	return func(options *options) {
		options.serverIdleTimeout = value
	}
}

// WithServerReadHeaderTimeout sets the read header timeout.
func WithServerReadHeaderTimeout(value time.Duration) Opt {
	return func(options *options) {
		options.serverReadHeaderTimeout = value
	}
}

// WithTracingEnabled enables/disables OpenTelemetry tracing.
func WithTracingEnabled(enable bool) Opt {
	return func(options *options) {
		options.tracingEnabled = enable
	}
}

// WithTracingServiceName sets the name of the OpenTelemetry service.
func WithTracingServiceName(serviceName string) Opt {
	return func(options *options) {
		options.tracingServiceName = serviceName
	}
}

// New returns a new HTTP server.
func New(url string, opts ...Opt) *Server {
	options := &options{
		serverIdleTimeout:       defaultServerIdleTimeout,
		serverReadHeaderTimeout: defaultServerReadHeaderTimeout,
	}

	for _, opt := range opts {
		opt(options)
	}

	s := &Server{
		certFile: options.certFile,
		keyFile:  options.keyFile,
	}

	router := mux.NewRouter()

	if options.tracingEnabled {
		router.Use(otelmux.Middleware(options.tracingServiceName))
	}

	for _, handler := range options.handlers {
		logger.Info("Registering handler", logfields.WithServiceEndpoint(handler.Path()))

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
		IdleTimeout: options.serverIdleTimeout,
		CountError: func(errType string) {
			logger.Error("HTTP2 server error", log.WithError(errors.New(errType)))
		},
	}

	httpServ := &http.Server{
		Addr:              url,
		Handler:           h2c.NewHandler(handler, http2Server),
		IdleTimeout:       options.serverIdleTimeout,
		ReadHeaderTimeout: options.serverReadHeaderTimeout,
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
