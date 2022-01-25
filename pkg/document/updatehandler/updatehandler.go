/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package updatehandler

import (
	"time"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

type metricsProvider interface {
	DocumentCreateUpdateTime(duration time.Duration)
}

// Option is an option for update handler.
type Option func(opts *UpdateHandler)

// UpdateHandler handles the creation and update of documents.
type UpdateHandler struct {
	coreProcessor dochandler.Processor
	metrics       metricsProvider
}

// New creates a new document update handler.
func New(processor dochandler.Processor, metrics metricsProvider, opts ...Option) *UpdateHandler {
	dh := &UpdateHandler{
		coreProcessor: processor,
		metrics:       metrics,
	}

	// apply options
	for _, opt := range opts {
		opt(dh)
	}

	return dh
}

// Namespace returns the namespace of the document handler.
func (r *UpdateHandler) Namespace() string {
	return r.coreProcessor.Namespace()
}

// ProcessOperation validates operation and adds it to the batch.
func (r *UpdateHandler) ProcessOperation(operationBuffer []byte, protocolVersion uint64) (*document.ResolutionResult, error) { //nolint:lll
	startTime := time.Now()

	defer func() {
		r.metrics.DocumentCreateUpdateTime(time.Since(startTime))
	}()

	doc, err := r.coreProcessor.ProcessOperation(operationBuffer, protocolVersion)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
