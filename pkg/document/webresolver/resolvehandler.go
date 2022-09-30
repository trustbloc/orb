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

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"

	"github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	diddoctransformer "github.com/trustbloc/orb/pkg/orbclient/doctransformer"
)

var logger = log.NewStructured("did-web-resolver")

// ResolveHandler resolves generic documents.
type ResolveHandler struct {
	orbResolver            orbResolver
	orbPrefix              string
	orbUnpublishedDIDLabel string

	allowedDomains map[string]bool

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
func NewResolveHandler(domains []*url.URL, orbPrefix, orbUnpublishedLabel string, resolver orbResolver,
	metrics metricsProvider) *ResolveHandler {
	allowedDomains := make(map[string]bool)

	for _, domain := range domains {
		domainWithPort := strings.ReplaceAll(domain.Host, ":", "%3A")
		allowedDomains[domainWithPort] = true
	}

	rh := &ResolveHandler{
		allowedDomains:         allowedDomains,
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

	didURL, err := did.Parse(id)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(didURL.MethodSpecificID, ":")

	// there has to be three parts: domain+port, scid, suffix
	const methodSpecificParts = 3

	if len(parts) != methodSpecificParts {
		return nil, fmt.Errorf("method specific id[%s] must have three parts", didURL.MethodSpecificID)
	}

	if parts[1] != "scid" {
		return nil, fmt.Errorf("method specific id[%s] must contain scid", didURL.MethodSpecificID)
	}

	hostWithPort := parts[0]

	if _, ok := r.allowedDomains[hostWithPort]; !ok {
		return nil, fmt.Errorf("domain not supported: %s", hostWithPort)
	}

	suffix := parts[2]

	unpublishedOrbDID := r.orbPrefix + docutil.NamespaceDelimiter +
		r.orbUnpublishedDIDLabel + docutil.NamespaceDelimiter + suffix

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

	didWebDoc, err := diddoctransformer.WebDocumentFromOrbDocument(id, localResponse)
	if err != nil {
		return nil, err
	}

	result := &document.ResolutionResult{Document: didWebDoc, Context: localResponse.Context}

	logger.Debug("Resolved DID", log.WithDID(id), log.WithResolutionResult(result))

	return result, nil
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
