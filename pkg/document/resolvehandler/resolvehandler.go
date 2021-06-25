/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/dochandler"
)

var logger = log.New("orb-resolver")

const (
	delimiter         = ":"
	minOrbSuffixParts = 2
)

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	coreResolver dochandler.Resolver
	discovery    discovery
	store        storage.Store

	namespace           string
	aliases             []string
	unpublishedDIDLabel string
	enableDidDiscovery  bool

	enableCreateDocumentStore bool
}

// did discovery service.
type discovery interface {
	RequestDiscovery(id string) error
}

// Option is an option for resolve handler.
type Option func(opts *ResolveHandler)

// WithEnableDIDDiscovery sets optional did discovery flag.
func WithEnableDIDDiscovery(enable bool) Option {
	return func(opts *ResolveHandler) {
		opts.enableDidDiscovery = enable
	}
}

// WithAliases sets optional aliases.
func WithAliases(aliases []string) Option {
	return func(opts *ResolveHandler) {
		opts.aliases = aliases
	}
}

// WithUnpublishedDIDLabel sets did label.
func WithUnpublishedDIDLabel(label string) Option {
	return func(opts *ResolveHandler) {
		opts.unpublishedDIDLabel = label
	}
}

// WithCreateDocumentStore will enable resolution from 'create' document store in case
// that document is not found in operations store.
func WithCreateDocumentStore(store storage.Store) Option {
	return func(opts *ResolveHandler) {
		opts.store = store
		opts.enableCreateDocumentStore = true
	}
}

// NewResolveHandler returns a new document resolve handler.
func NewResolveHandler(namespace string, resolver dochandler.Resolver, discovery discovery, opts ...Option) *ResolveHandler { //nolint:lll
	rh := &ResolveHandler{
		namespace:    namespace,
		coreResolver: resolver,
		discovery:    discovery,
	}

	// apply options
	for _, opt := range opts {
		opt(rh)
	}

	return rh
}

// ResolveDocument resolves a document.
func (r *ResolveHandler) ResolveDocument(id string) (*document.ResolutionResult, error) {
	response, err := r.coreResolver.ResolveDocument(id)
	if err != nil { //nolint:nestif
		if strings.Contains(err.Error(), "not found") {
			if strings.Contains(id, r.unpublishedDIDLabel) {
				if r.enableCreateDocumentStore {
					createDocResponse, createDocErr := r.resolveDocumentFromCreateDocumentStore(id)
					if createDocErr != nil {
						// return original error (create document store is just convenience)
						return nil, err
					}

					logger.Debugf("successfully resolved id[%s] from create document store", id)

					return createDocResponse, nil
				}
			} else {
				if r.enableDidDiscovery {
					r.requestDiscovery(id)
				}
			}
		}

		return nil, err
	}

	// document was retrieved from operation store

	if strings.Contains(id, r.unpublishedDIDLabel) && r.enableCreateDocumentStore {
		// delete interim document from create document store
		r.deleteDocumentFromCreateDocumentStore(id)
	}

	return response, nil
}

func (r *ResolveHandler) deleteDocumentFromCreateDocumentStore(id string) {
	deleteErr := r.store.Delete(id)
	if deleteErr != nil {
		logger.Warnf("failed to delete id[%s] from create document store: %s", id, deleteErr.Error())
	} else {
		logger.Debugf("deleted id[%s] from create document store", id)
	}
}

func (r *ResolveHandler) resolveDocumentFromCreateDocumentStore(id string) (*document.ResolutionResult, error) {
	createDocBytes, err := r.store.Get(id)
	if err != nil {
		if !errors.Is(err, storage.ErrDataNotFound) {
			logger.Warnf("failed to retrieve id[%s] from create document store: %s", id, err.Error())
		}

		return nil, err
	}

	var rr document.ResolutionResult

	err = json.Unmarshal(createDocBytes, &rr)
	if err != nil {
		logger.Warnf("failed to marshal document id[%s] from create document store: %s", id, err.Error())

		return nil, err
	}

	return &rr, nil
}

func (r *ResolveHandler) requestDiscovery(id string) {
	orbSuffix, err := r.getOrbSuffix(id)
	if err != nil {
		// not proper orb suffix - nothing to do
		logger.Debugf("get orb suffix from id[%s] error: %s", id, err.Error())

		return
	}

	logger.Infof("requesting discovery for orb suffix[%s]", orbSuffix)

	err = r.discovery.RequestDiscovery(orbSuffix)
	if err != nil {
		logger.Warnf("error while requesting discovery for orb suffix[%s]: %s", orbSuffix, err.Error())
	}
}

func (r *ResolveHandler) getNamespace(shortFormDID string) (string, error) {
	if strings.HasPrefix(shortFormDID, r.namespace+delimiter) {
		return r.namespace, nil
	}

	// check aliases
	for _, ns := range r.aliases {
		if strings.HasPrefix(shortFormDID, ns+delimiter) {
			return ns, nil
		}
	}

	return "", fmt.Errorf("did must start with configured namespace[%s] or aliases%v", r.namespace, r.aliases)
}

// getOrbSuffix fetches unique portion of ID which is string after namespace.
// Valid Orb suffix has two parts cas hint + cid:suffix.
func (r *ResolveHandler) getOrbSuffix(shortFormDID string) (string, error) {
	namespace, err := r.getNamespace(shortFormDID)
	if err != nil {
		return "", err
	}

	orbSuffix := shortFormDID[len(namespace+delimiter):]

	parts := strings.Split(orbSuffix, delimiter)
	if len(parts) < minOrbSuffixParts {
		return "", fmt.Errorf("invalid number of parts for orb suffix[%s]", orbSuffix)
	}

	return orbSuffix, nil
}
