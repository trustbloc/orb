/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

var logger = log.New("log-monitor-handler")

// New creates new proof handler.
func New(store logMonitorStore, logResolver logResolver) *Handler {
	return &Handler{
		store:       store,
		logResolver: logResolver,
	}
}

// Handler handles registering/un-registering log for monitoring.
type Handler struct {
	store       logMonitorStore
	logResolver logResolver
}

type logMonitorStore interface {
	Activate(logURL string) error
}

type logResolver interface {
	ResolveLog(uri string) (*url.URL, error)
}

// Accept will get actor's log to the list of logs to be monitored by log monitoring service.
func (h *Handler) Accept(actor *url.URL) error {
	logger.Debugf("received request to add log for actor: %s", actor.String())

	domainURL := fmt.Sprintf("%s://%s", actor.Scheme, actor.Host)

	logURL, err := h.logResolver.ResolveLog(domainURL)
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Infof("domain[%s] doesn't have log", domainURL)

			return nil
		}

		return fmt.Errorf("failed to resolve log for domain[%s]: %w", domainURL, err)
	}

	logger.Debugf("retrieved logURL[%s] for domain[%s]", logURL.String(), domainURL)

	err = h.store.Activate(logURL.String())
	if err != nil {
		return fmt.Errorf("failed to add logURL[%s] for monitoring: %w", logURL, err)
	}

	logger.Debugf("added logURL[%s] for monitoring", logURL.String())

	return nil
}
