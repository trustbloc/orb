/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"go.opentelemetry.io/otel/trace"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

var logger = log.New("anchor-credential-handler")

type anchorLinkStore interface {
	GetProcessedAndPendingLinks(anchorHash string) ([]*url.URL, error)
	PutPendingLinks(links []*url.URL) error
	DeletePendingLinks(links []*url.URL) error
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
	tracer            trace.Tracer
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, string, error)
}

type anchorPublisher interface {
	PublishAnchor(ctx context.Context, anchorInfo *anchorinfo.AnchorInfo) error
}

// New creates new credential handler.
func New(anchorPublisher anchorPublisher, casResolver casResolver,
	documentLoader ld.DocumentLoader,
	maxDelay time.Duration, anchorLinkStore anchorLinkStore,
	registry generatorRegistry,
) *AnchorEventHandler {
	return &AnchorEventHandler{
		anchorPublisher:   anchorPublisher,
		maxDelay:          maxDelay,
		casResolver:       casResolver,
		documentLoader:    documentLoader,
		anchorLinkStore:   anchorLinkStore,
		generatorRegistry: registry,
		unmarshal:         json.Unmarshal,
		tracer:            tracing.Tracer(tracing.SubsystemAnchor),
	}
}

// HandleAnchorEvent handles an anchor event.
//
//nolint:cyclop
func (h *AnchorEventHandler) HandleAnchorEvent(ctx context.Context, actor, anchorRef, source *url.URL,
	anchorEvent *vocab.AnchorEventType,
) error {
	logger.Debugc(ctx, "Received request for anchor", logfields.WithActorIRI(actor), logfields.WithAnchorURI(anchorRef))

	ok, err := h.isAnchorProcessed(anchorRef)
	if err != nil {
		return fmt.Errorf("is anchor processed [%s]: %w", anchorRef, err)
	}

	if ok {
		logger.Infoc(ctx, "Anchor was already processed or processing is pending", logfields.WithAnchorURI(anchorRef))

		return nil
	}

	var anchorLinksetBytes []byte

	if anchorEvent != nil {
		var e error

		anchorLinksetBytes, e = canonicalizer.MarshalCanonical(anchorEvent.Object().Document())
		if e != nil {
			return fmt.Errorf("marshal anchor linkset: %w", e)
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
	err = h.ensureParentAnchorsAreProcessed(ctx, anchorRef, anchorLink)
	if err != nil {
		return fmt.Errorf("ensure unprocessed parents are processed for %s: %w", anchorRef, err)
	}

	var attributedTo string
	if actor != nil {
		attributedTo = actor.String()
	}

	logger.Infoc(ctx, "Processing anchor", logfields.WithAnchorURI(anchorRef))

	var alternateSources []string

	if source != nil {
		// The anchor index in the AnchorEvent may not be found in the CAS store. This may occur in the event that
		// the anchor origin lost the original data. So we add an alternate source from which the Sidetree
		// files may be retrieved.
		alternateSources = []string{source.String()}
	}

	// Now process the latest anchor event.
	err = h.processAnchorEvent(ctx, &anchorInfo{
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

func (h *AnchorEventHandler) processAnchorEvent(ctx context.Context, anchorInfo *anchorInfo) error {
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

	hl, err := url.Parse(anchorInfo.Hashlink)
	if err != nil {
		return fmt.Errorf("parse anchor hashlink [%s]: %w", anchorInfo.Hashlink, err)
	}

	// Check again if the anchor was processed. This further limits race conditions, especially
	// when many anchors with the same parent are being processed concurrently.
	processed, err := h.isAnchorProcessed(hl)
	if err != nil {
		return fmt.Errorf("is anchor processed [%s]: %w", hl, err)
	}

	if processed {
		logger.Infoc(ctx, "Anchor was already processed or processing is pending.", logfields.WithAnchorURI(hl))

		return nil
	}

	logger.Debugc(ctx, "Storing pending anchor link", logfields.WithAnchorURI(hl))

	err = h.anchorLinkStore.PutPendingLinks([]*url.URL{hl})
	if err != nil {
		return fmt.Errorf("store pending anchor link: %w", err)
	}

	err = h.anchorPublisher.PublishAnchor(ctx, anchorInfo.AnchorInfo)
	if err != nil {
		logger.Warn("Error publishing anchor. Deleting pending links so that when the anchor event is retried, "+
			"the pending state of the anchor won't prevent processing.", log.WithError(err), logfields.WithAnchorURI(hl))

		if e := h.anchorLinkStore.DeletePendingLinks([]*url.URL{hl}); e != nil {
			logger.Error("Error deleting pending links for anchor. The DIDs in this anchor may remain un-anchored.",
				log.WithError(e), logfields.WithAnchorURI(hl))
		}

		return fmt.Errorf("publish anchor %s: %w", hl, err)
	}

	return nil
}

// ensureParentAnchorsAreProcessed checks all ancestors (parents, grandparents, etc.) of the given anchor event
// and processes all that have not yet been processed.
func (h *AnchorEventHandler) ensureParentAnchorsAreProcessed(ctx context.Context, anchorRef *url.URL, anchorLink *linkset.Link) error {
	unprocessedParents, err := h.getUnprocessedParentAnchors(anchorRef.String(), anchorLink)
	if err != nil {
		return fmt.Errorf("get unprocessed parent anchors for [%s]: %w", anchorRef, err)
	}

	if len(unprocessedParents) == 0 {
		return nil
	}

	logger.Infoc(ctx, "Processing parents of anchor", logfields.WithTotal(len(unprocessedParents)),
		logfields.WithAnchorURI(anchorRef), logfields.WithParents(unprocessedParents.HashLinks()))

	spanCtx, span := h.tracer.Start(ctx, "process parent anchors",
		trace.WithAttributes(tracing.AnchorEventURIAttribute(anchorRef.String())))
	defer span.End()

	for _, parentAnchorInfo := range unprocessedParents {
		logger.Debugc(spanCtx, "Processing parent", logfields.WithAnchorURI(anchorRef), logfields.WithParent(parentAnchorInfo.Hashlink))

		err = h.processAnchorEvent(spanCtx, parentAnchorInfo)
		if err != nil {
			return fmt.Errorf("process anchor [%s]: %w", parentAnchorInfo.Hashlink, err)
		}
	}

	return nil
}

// getUnprocessedParentAnchors returns all unprocessed ancestors (parents, grandparents, etc.) of the given
// anchor event, sorted by oldest to newest.
//
//nolint:cyclop
func (h *AnchorEventHandler) getUnprocessedParentAnchors(hl string, anchorLink *linkset.Link) (anchorInfoSlice, error) {
	logger.Debug("Getting unprocessed parents of anchor", logfields.WithAnchorURIString(hl))

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
				logfields.WithAnchorURIString(hl), logfields.WithParentURI(parentHL))

			continue
		}

		processedOrPending, info, err := h.getUnprocessedParentAnchor(hl, parentHL)
		if err != nil {
			return nil, err
		}

		if processedOrPending {
			continue
		}

		logger.Debug("Adding parent of anchor event to the unprocessed list",
			logfields.WithAnchorURIString(hl), logfields.WithParentURI(parentHL))

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
		logfields.WithAnchorURIString(hl), logfields.WithParentURI(parentHL))

	isProcessed, err := h.isAnchorProcessed(parentHL)
	if err != nil {
		return false, nil, fmt.Errorf("is anchor processed [%s]: %w", parentHL, err)
	}

	if isProcessed {
		logger.Debug("Parent of anchor was already processed or processing is pending",
			logfields.WithAnchorURIString(hl), logfields.WithParentURI(parentHL))

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

	links, err := h.anchorLinkStore.GetProcessedAndPendingLinks(hash)
	if err != nil {
		return false, fmt.Errorf("get anchor event: %w", err)
	}

	for _, link := range links {
		if link.String() == hl.String() {
			return true, nil
		}
	}

	return false, nil
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
