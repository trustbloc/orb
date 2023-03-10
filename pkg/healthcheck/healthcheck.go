/*
   Copyright SecureKey Technologies Inc.

   This file contains software code that is the intellectual property of SecureKey.
   SecureKey reserves all rights in the code and you may not use it without
	 written permission from SecureKey.
*/

package healthcheck

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/vct"
)

var logger = log.New("healthcheck")

const (
	healthCheckEndpoint = "/healthcheck"

	success      = "success"
	notConnected = "not connected"
	unknown      = "unknown error"
)

// Handler implements a health check HTTP handler.
type Handler struct {
	pubSub          pubSub
	vct             vctService
	db              db
	keyManager      keyManager
	maintenanceMode bool
}

type pubSub interface {
	IsConnected() bool
}

type vctService interface {
	HealthCheck() error
}

type db interface {
	Ping() error
}

type keyManager interface {
	HealthCheck() error
}

// NewHandler returns a new health check handler.
func NewHandler(pubSub pubSub, vctService vctService, db db, keyManager keyManager, maintenanceMode bool) *Handler {
	return &Handler{
		pubSub:          pubSub,
		vct:             vctService,
		db:              db,
		keyManager:      keyManager,
		maintenanceMode: maintenanceMode,
	}
}

// Method returns the HTTP method, which is always POST.
func (h *Handler) Method() string {
	return http.MethodGet
}

// Path returns the base path of the target URL for this handler.
func (h *Handler) Path() string {
	return healthCheckEndpoint
}

// Handler returns the handler that should be invoked when an HTTP POST is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *Handler) Handler() common.HTTPRequestHandler {
	return h.checkHealth
}

type response struct {
	MQStatus    string    `json:"mqStatus,omitempty"`
	VCTStatus   string    `json:"vctStatus,omitempty"`
	DBStatus    string    `json:"dbStatus,omitempty"`
	KMSStatus   string    `json:"kmsStatus,omitempty"`
	Status      string    `json:"status,omitempty"`
	CurrentTime time.Time `json:"currentTime,omitempty"`
	Version     string    `json:"version,omitempty"`
}

func (h *Handler) checkHealth(rw http.ResponseWriter, _ *http.Request) {
	var mqStatus, vctStatus, dbStatus, kmsStatus string

	returnStatusServiceUnavailable := false

	unavailable, mqStatus := h.mqHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, vctStatus = h.vctHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, dbStatus = h.dbHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	unavailable, kmsStatus = h.kmsHealthCheck()
	if unavailable {
		returnStatusServiceUnavailable = true
	}

	status := http.StatusOK

	if returnStatusServiceUnavailable {
		status = http.StatusServiceUnavailable
	}

	hc := &response{
		MQStatus:    mqStatus,
		VCTStatus:   vctStatus,
		DBStatus:    dbStatus,
		KMSStatus:   kmsStatus,
		CurrentTime: time.Now(),
		Status:      "OK",
		Version:     httpserver.BuildVersion,
	}

	if h.maintenanceMode {
		// server has been started in maintenance mode so we should return 200 from health check
		// even if health check is failing in order to give an admin opportunity to fix system configuration
		status = http.StatusOK
		hc.Status = "Maintenance"
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

func (h *Handler) mqHealthCheck() (bool, string) {
	if h.pubSub == nil {
		return false, ""
	}

	if h.pubSub.IsConnected() {
		return false, success
	}

	return true, notConnected
}

func (h *Handler) vctHealthCheck() (bool, string) {
	if h.vct == nil {
		return false, ""
	}

	err := h.vct.HealthCheck()
	if err == nil {
		return false, success
	}

	if errors.Is(err, vct.ErrLogEndpointNotConfigured) || errors.Is(err, vct.ErrDisabled) {
		// It's not an error if VCT is disabled or no log endpoint was configured.
		// Return the message so that the client knows the status of VCT.
		return false, err.Error()
	}

	return true, toStatus(err)
}

func (h *Handler) dbHealthCheck() (bool, string) {
	if h.db == nil {
		return false, ""
	}

	err := h.db.Ping()
	if err == nil {
		return false, success
	}

	return true, toStatus(err)
}

func (h *Handler) kmsHealthCheck() (bool, string) {
	if h.keyManager == nil {
		return false, ""
	}

	err := h.keyManager.HealthCheck()
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
