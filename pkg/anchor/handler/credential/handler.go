/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/linkset"
)

var logger = log.New("anchor-credential-handler")

type anchorLinkStore interface {
	GetLinks(anchorHash string) ([]*url.URL, error)
}

type generatorRegistry interface {
	Get(id *url.URL) (generator.Generator, error)
}

// AnchorEventHandler handles a new, published anchor credential.
type AnchorEventHandler struct {
	anchorPublisher   anchorPublisher
	casResolver       casResolver
	maxDelay          time.Duration
	documentLoader    ld.DocumentLoader
	anchorLinkStore   anchorLinkStore
	unmarshal         func(data []byte, v interface{}) error
	generatorRegistry generatorRegistry
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, string, error)
}

type anchorPublisher interface {
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
}

// New creates new credential handler.
func New(anchorPublisher anchorPublisher, casResolver casResolver,
	documentLoader ld.DocumentLoader,
	maxDelay time.Duration, anchorLinkStore anchorLinkStore,
	registry generatorRegistry) *AnchorEventHandler {
	return &AnchorEventHandler{
		anchorPublisher:   anchorPublisher,
		maxDelay:          maxDelay,
		casResolver:       casResolver,
		documentLoader:    documentLoader,
		anchorLinkStore:   anchorLinkStore,
		generatorRegistry: registry,
		unmarshal:         json.Unmarshal,
	}
}

// HandleAnchorEvent handles an anchor event.
//
//nolint:cyclop
func (h *AnchorEventHandler) HandleAnchorEvent(actor, anchorRef, source *url.URL,
	anchorEvent *vocab.AnchorEventType) error {
	logger.Debug("Received request for anchor", log.WithActorIRI(actor), log.WithAnchorEventURI(anchorRef))

	var anchorLinksetBytes []byte

	if anchorEvent != nil {
		var err error

		anchorLinksetBytes, err = canonicalizer.MarshalCanonical(anchorEvent.Object().Document())
		if err != nil {
			return fmt.Errorf("marshal anchor linkset: %w", err)
		}
	}

	anchorLinksetBytes, localHL, err := h.casResolver.Resolve(nil, anchorRef.String(), anchorLinksetBytes)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor [%s]: %w", anchorRef, err)
	}

	anchorLinkset := &linkset.Linkset{}

	err = h.unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return fmt.Errorf("unmarshal anchor: %w", err)
	}

	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return fmt.Errorf("anchor Linkset [%s] is empty", anchorRef)
	}

	err = anchorLink.Validate()
	if err != nil {
		return fmt.Errorf("validate anchor link: %w", err)
	}

	// Make sure that all parents/grandparents of this anchor event are processed.
	err = h.ensureParentAnchorsAreProcessed(anchorRef, anchorLink)
	if err != nil {
		return fmt.Errorf("ensure unprocessed parents are processed for %s: %w", anchorRef, err)
	}

	var attributedTo string
	if actor != nil {
		attributedTo = actor.String()
	}

	logger.Info("Processing anchor", log.WithAnchorEventURI(anchorRef))

	var alternateSources []string

	if source != nil {
		// The anchor index in the AnchorEvent may not be found in the CAS store. This may occur in the event that
		// the anchor origin lost the original data. So we add an alternate source from which the Sidetree
		// files may be retrieved.
		alternateSources = []string{source.String()}
	}

	// Now process the latest anchor event.
	err = h.processAnchorEvent(&anchorInfo{
		anchorLink: anchorLink,
		AnchorInfo: &anchorinfo.AnchorInfo{
			Hashlink:         anchorRef.String(),
			LocalHashlink:    localHL,
			AttributedTo:     attributedTo,
			AlternateSources: alternateSources,
		},
	})
	if err != nil {
		return fmt.Errorf("process anchor %s: %w", anchorRef, err)
	}

	return nil
}

func (h *AnchorEventHandler) processAnchorEvent(anchorInfo *anchorInfo) error {
	anchorLink := anchorInfo.anchorLink

	contentBytes, err := anchorLink.Original().Content()
	if err != nil {
		return fmt.Errorf("get content from original: %w", err)
	}

	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLink,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.documentLoader),
		verifiable.WithStrictValidation(),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor link: %w", err)
	}

	gen, err := h.generatorRegistry.Get(anchorLink.Profile())
	if err != nil {
		return fmt.Errorf("resolve generator for profile [%s]: %w", anchorLink.Profile(), err)
	}

	err = gen.ValidateAnchorCredential(vc, contentBytes)
	if err != nil {
		return fmt.Errorf("validate credential subject for anchor [%s]: %w", anchorLink.Anchor(), err)
	}

	return h.anchorPublisher.PublishAnchor(anchorInfo.AnchorInfo)
}

// ensureParentAnchorsAreProcessed checks all ancestors (parents, grandparents, etc.) of the given anchor event
// and processes all that have not yet been processed.
func (h *AnchorEventHandler) ensureParentAnchorsAreProcessed(anchorRef *url.URL, anchorLink *linkset.Link) error {
	unprocessedParents, err := h.getUnprocessedParentAnchors(anchorRef.String(), anchorLink)
	if err != nil {
		return fmt.Errorf("get unprocessed parent anchors for [%s]: %w", anchorRef, err)
	}

	logger.Debug("Processing parents of anchor", log.WithTotal(len(unprocessedParents)),
		log.WithAnchorURI(anchorRef), log.WithParents(unprocessedParents.HashLinks()))

	for _, parentAnchorInfo := range unprocessedParents {
		logger.Info("Processing parent", log.WithAnchorURI(anchorRef), log.WithParent(parentAnchorInfo.Hashlink))

		err = h.processAnchorEvent(parentAnchorInfo)
		if err != nil {
			return fmt.Errorf("process anchor [%s]: %w", parentAnchorInfo.Hashlink, err)
		}
	}

	return nil
}

// getUnprocessedParentAnchors returns all unprocessed ancestors (parents, grandparents, etc.) of the given
// anchor event, sorted by oldest to newest.
//
//nolint: cyclop,goimports
func (h *AnchorEventHandler) getUnprocessedParentAnchors(hl string, anchorLink *linkset.Link) (anchorInfoSlice, error) {
	logger.Debug("Getting unprocessed parents of anchor", log.WithAnchorURIString(hl))

	if anchorLink.Related() == nil {
		return nil, nil
	}

	relatedLinkset, err := anchorLink.Related().Linkset()
	if err != nil {
		return nil, fmt.Errorf("invalid related Linkset: %w", err)
	}

	relatedLink := relatedLinkset.Link()
	if relatedLink == nil {
		return nil, fmt.Errorf("related Linkset is empty")
	}

	if relatedLink.Anchor() == nil || relatedLink.Anchor().String() != anchorLink.Anchor().String() {
		return nil, fmt.Errorf("anchor of related Linkset [%s] is not equal to the expected anchor [%s]",
			relatedLink.Anchor(), hl)
	}

	var unprocessed []*anchorInfo

	for _, parentHL := range relatedLink.Up() {
		if containsAnchor(unprocessed, parentHL.String()) {
			logger.Debug("Not adding parent of anchor to the unprocessed list since it has already been added",
				log.WithAnchorURIString(hl), log.WithParentURI(parentHL))

			continue
		}

		processed, info, err := h.getUnprocessedParentAnchor(hl, parentHL)
		if err != nil {
			return nil, err
		}

		if processed {
			continue
		}

		logger.Debug("Adding parent of anchor event to the unprocessed list",
			log.WithAnchorEventURIString(hl), log.WithParentURI(parentHL))

		// Add the parent to the head of the list since it needs to be processed first.
		unprocessed = append([]*anchorInfo{info}, unprocessed...)

		ancestorAnchors, err := h.getUnprocessedParentAnchors(parentHL.String(), info.anchorLink)
		if err != nil {
			return nil, fmt.Errorf("get unprocessed anchors for parent [%s]: %w", parentHL, err)
		}

		unprocessed = prependAnchors(unprocessed, ancestorAnchors)
	}

	return unprocessed, nil
}

func (h *AnchorEventHandler) getUnprocessedParentAnchor(hl string, parentHL *url.URL) (bool, *anchorInfo, error) {
	logger.Debug("Checking parent of anchor to see if it has been processed",
		log.WithAnchorURIString(hl), log.WithParentURI(parentHL))

	isProcessed, err := h.isAnchorProcessed(parentHL)
	if err != nil {
		return false, nil, fmt.Errorf("is anchor processed [%s]: %w", parentHL, err)
	}

	if isProcessed {
		logger.Debug("Parent of anchor was already processed",
			log.WithAnchorURIString(hl), log.WithParentURI(parentHL))

		return true, nil, nil
	}

	anchorLinksetBytes, localHL, err := h.casResolver.Resolve(nil, parentHL.String(), nil)
	if err != nil {
		return false, nil, fmt.Errorf("resolve anchor [%s]: %w", parentHL, err)
	}

	parentAnchorLinkset := &linkset.Linkset{}

	err = h.unmarshal(anchorLinksetBytes, parentAnchorLinkset)
	if err != nil {
		return false, nil, fmt.Errorf("unmarshal anchor Linkset: %w", err)
	}

	parentAnchorLink := parentAnchorLinkset.Link()

	if parentAnchorLink == nil {
		return false, nil, fmt.Errorf("parent Linkset [%s] is empty", parentHL)
	}

	return false, &anchorInfo{
		anchorLink: parentAnchorLink,
		AnchorInfo: &anchorinfo.AnchorInfo{
			Hashlink:      parentHL.String(),
			LocalHashlink: localHL,
		},
	}, nil
}

func prependAnchors(existingAnchors, newAnchors []*anchorInfo) []*anchorInfo {
	resultingAnchors := existingAnchors

	for _, anchor := range newAnchors {
		if !containsAnchor(resultingAnchors, anchor.Hashlink) {
			// Add the ancestor to the head of the list since it needs to be processed first.
			resultingAnchors = append([]*anchorInfo{anchor}, resultingAnchors...)
		}
	}

	return resultingAnchors
}

func containsAnchor(existingAnchors []*anchorInfo, hl string) bool {
	for _, anchor := range existingAnchors {
		if anchor.Hashlink == hl {
			return true
		}
	}

	return false
}

func (h *AnchorEventHandler) isAnchorProcessed(hl *url.URL) (bool, error) {
	hash, err := hashlink.GetResourceHashFromHashLink(hl.String())
	if err != nil {
		return false, fmt.Errorf("parse hashlink: %w", err)
	}

	links, err := h.anchorLinkStore.GetLinks(hash)
	if err != nil {
		return false, fmt.Errorf("get anchor event: %w", err)
	}

	return len(links) > 0, nil
}

type anchorInfo struct {
	*anchorinfo.AnchorInfo
	anchorLink *linkset.Link
}

type anchorInfoSlice []*anchorInfo

func (s anchorInfoSlice) HashLinks() []string {
	hashlinks := make([]string, len(s))

	for i, ai := range s {
		hashlinks[i] = ai.Hashlink
	}

	return hashlinks
}
