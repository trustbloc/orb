/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webresolver

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

var logger = log.New("did-web-resolver")

// ErrDocumentNotFound is document not found error.
var ErrDocumentNotFound = fmt.Errorf("document not found")

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
	ResolveDocument(id string) (*document.ResolutionResult, error)
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
			return nil, ErrDocumentNotFound
		}

		return nil, fmt.Errorf("failed to resolve document for id[%s]: %w", id, err)
	}

	alsoKnownAs := getAlsoKnownAs(localResponse.Document)

	webDID := fmt.Sprintf("did:web:%s:identity:%s", r.domain.Host, id)

	if !contains(alsoKnownAs, webDID) {
		// TODO: is this legit error message (should we allow it even if it is not in also known as)
		return nil, fmt.Errorf("id[%s] not found in alsoKnownAs", webDID)
	}

	didWebDoc, err := transformToDIDWeb(id, localResponse.Document)
	if err != nil {
		return nil, err
	}

	logger.Debugf("resolved id: %s", id)

	return &document.ResolutionResult{Document: didWebDoc}, nil
}

func transformToDIDWeb(id string, doc document.Document) (document.Document, error) {
	docBytes, err := doc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document for id[%s]: %w", id, err)
	}

	// replace all occurrences of did:orb ID with did:web ID
	didWebDocStr := strings.ReplaceAll(string(docBytes), doc.ID(), id)

	var didWebDoc document.Document

	err = json.Unmarshal([]byte(didWebDocStr), &didWebDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal document for id[%s]: %w", id, err)
	}

	return didWebDoc, nil
}

func getAlsoKnownAs(doc document.Document) []string {
	didDoc := document.DidDocumentFromJSONLDObject(doc)

	return didDoc.AlsoKnownAs()
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}
