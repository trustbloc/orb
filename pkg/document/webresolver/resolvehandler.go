/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webresolver

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	diddoctransformer "github.com/trustbloc/orb/pkg/orbclient/doctransformer"
)

var logger = log.New("did-web-resolver")

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	orbResolver            orbResolver
	orbPrefix              string
	orbUnpublishedDIDLabel string

	domain *url.URL

	metrics metricsProvider
}

// Orb resolver resolves Orb documents.
type orbResolver interface {
	ResolveDocument(id string, opts ...document.ResolutionOption) (*document.ResolutionResult, error)
}

type metricsProvider interface {
	WebDocumentResolveTime(duration time.Duration)
}

// NewResolveHandler returns a new document resolve handler.
func NewResolveHandler(domain *url.URL, orbPrefix, orbUnpublishedLabel string, resolver orbResolver,
	metrics metricsProvider) *ResolveHandler {
	rh := &ResolveHandler{
		domain:                 domain,
		orbPrefix:              orbPrefix,
		orbResolver:            resolver,
		metrics:                metrics,
		orbUnpublishedDIDLabel: orbUnpublishedLabel,
	}

	return rh
}

// ResolveDocument resolves a document.
func (r *ResolveHandler) ResolveDocument(id string) (*document.ResolutionResult, error) {
	startTime := time.Now()

	defer func() {
		r.metrics.WebDocumentResolveTime(time.Since(startTime))
	}()

	unpublishedOrbDID := r.orbPrefix + docutil.NamespaceDelimiter +
		r.orbUnpublishedDIDLabel + docutil.NamespaceDelimiter + id

	localResponse, err := r.orbResolver.ResolveDocument(unpublishedOrbDID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, orberrors.ErrContentNotFound
		}

		return nil, fmt.Errorf("failed to resolve document for id[%s]: %w", id, err)
	}

	deactivated := getDeactivatedFlag(localResponse)
	if deactivated {
		return nil, orberrors.ErrContentNotFound
	}

	domainWithPort := strings.ReplaceAll(r.domain.Host, ":", "%3A")

	webDID := fmt.Sprintf("did:web:%s:scid:%s", domainWithPort, id)

	didWebDoc, err := diddoctransformer.WebDocumentFromOrbDocument(webDID, localResponse)
	if err != nil {
		return nil, err
	}

	logger.Debugf("resolved id: %s", id)

	return &document.ResolutionResult{Document: didWebDoc, Context: localResponse.Context}, nil
}

func getDeactivatedFlag(result *document.ResolutionResult) bool {
	deactivatedObj, ok := result.DocumentMetadata[document.DeactivatedProperty]
	if ok {
		deactivated, ok := deactivatedObj.(bool)
		if ok {
			return deactivated
		}
	}

	return false
}
