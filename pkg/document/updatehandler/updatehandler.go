/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package updatehandler

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

var logger = log.New("orb-update-handler")

// Option is an option for update handler.
type Option func(opts *UpdateHandler)

// WithCreateDocumentStore stores 'create' document response into create document store.
func WithCreateDocumentStore(store storage.Store) Option {
	return func(opts *UpdateHandler) {
		opts.store = store
		opts.createDocumentStoreEnabled = true
	}
}

// UpdateHandler handles the creation and update of documents.
type UpdateHandler struct {
	coreProcessor dochandler.Processor
	store         storage.Store

	createDocumentStoreEnabled bool
}

// New creates a new document update handler.
func New(processor dochandler.Processor, opts ...Option) *UpdateHandler {
	dh := &UpdateHandler{
		coreProcessor: processor,
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
func (r *UpdateHandler) ProcessOperation(operationBuffer []byte, protocolGenesisTime uint64) (*document.ResolutionResult, error) { //nolint:lll
	doc, err := r.coreProcessor.ProcessOperation(operationBuffer, protocolGenesisTime)
	if err != nil {
		return nil, err
	}

	if doc != nil && r.createDocumentStoreEnabled {
		// document is returned only in 'create' case
		r.storeResultToCreateDocumentStore(doc)
	}

	return doc, nil
}

func (r *UpdateHandler) storeResultToCreateDocumentStore(doc *document.ResolutionResult) {
	id := doc.Document.ID()

	docBytes, err := json.Marshal(doc)
	if err != nil {
		logger.Warnf("failed to marshal resolution result for create operation for id[%s]: %s", id, err.Error())

		return
	}

	err = r.store.Put(id, docBytes)
	if err != nil {
		logger.Warnf("failed to store create document id[%s] to create operation store: %s", id, err.Error())

		return
	}

	logger.Debugf("stored create document id[%s] result into create document store", id)
}
