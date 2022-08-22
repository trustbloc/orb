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

	orberrors "github.com/trustbloc/orb/pkg/errors"
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

	webDID := fmt.Sprintf("did:web:%s:scid:%s", r.domain.Host, id)

	didWebDoc, err := transformToDIDWeb(webDID, localResponse.Document)
	if err != nil {
		return nil, err
	}

	orbDID := getOrbDID(localResponse)

	// replace did:web ID with did:orb ID in also known as; if did:web ID is not found then add did:orb ID anyway
	didWebDoc, err = updateAlsoKnownAs(didWebDoc, webDID, orbDID)
	if err != nil {
		return nil, err
	}

	logger.Debugf("resolved id: %s", id)

	return &document.ResolutionResult{Document: didWebDoc, Context: localResponse.Context}, nil
}

func updateAlsoKnownAs(didWebDoc document.Document, webDID, orbDID string) (document.Document, error) {
	alsoKnownAs, err := getAlsoKnownAs(didWebDoc)
	if err != nil {
		return nil, err
	}

	// replace did:orb value with did:web values
	updatedAlsoKnownAs := updateValues(alsoKnownAs, webDID, orbDID)

	if !contains(updatedAlsoKnownAs, orbDID) {
		updatedAlsoKnownAs = append(updatedAlsoKnownAs, orbDID)
	}

	didWebDoc[document.AlsoKnownAs] = updatedAlsoKnownAs

	return didWebDoc, nil
}

func getOrbDID(result *document.ResolutionResult) string {
	canonicalIDObj, ok := result.DocumentMetadata[document.CanonicalIDProperty]
	if ok {
		canonicalID, ok := canonicalIDObj.(string)
		if ok {
			return canonicalID
		}
	}

	return result.Document.ID()
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

// updateValues will replace old value with new value in an array of strings.
func updateValues(values []string, oldValue, newValue string) []string {
	for i, v := range values {
		if v == oldValue {
			values[i] = newValue
		}
	}

	return values
}

func getAlsoKnownAs(doc document.Document) ([]string, error) {
	alsoKnownAsObj, ok := doc[document.AlsoKnownAs]
	if !ok || alsoKnownAsObj == nil {
		return nil, nil
	}

	alsoKnownAsObjArr, ok := alsoKnownAsObj.([]interface{})
	if ok {
		return document.StringArray(alsoKnownAsObjArr), nil
	}

	alsoKnownAsStrArr, ok := alsoKnownAsObj.([]string)
	if ok {
		return alsoKnownAsStrArr, nil
	}

	return nil, fmt.Errorf("unexpected interface '%T' for also known as", alsoKnownAsObj)
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

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}
