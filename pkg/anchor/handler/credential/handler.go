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
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/hashlink"
)

var logger = log.New("anchor-credential-handler")

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

type anchorLinkStore interface {
	GetLinks(anchorHash string) ([]*url.URL, error)
}

// AnchorEventHandler handles a new, published anchor credential.
type AnchorEventHandler struct {
	anchorPublisher anchorPublisher
	casResolver     casResolver
	maxDelay        time.Duration
	documentLoader  ld.DocumentLoader
	monitoringSvc   monitoringSvc
	anchorLinkStore anchorLinkStore
	unmarshal       func(data []byte, v interface{}) error
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, string, error)
}

type anchorPublisher interface {
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
}

// New creates new credential handler.
func New(anchorPublisher anchorPublisher, casResolver casResolver,
	documentLoader ld.DocumentLoader, monitoringSvc monitoringSvc,
	maxDelay time.Duration, anchorLinkStore anchorLinkStore) *AnchorEventHandler {
	return &AnchorEventHandler{
		anchorPublisher: anchorPublisher,
		maxDelay:        maxDelay,
		casResolver:     casResolver,
		documentLoader:  documentLoader,
		monitoringSvc:   monitoringSvc,
		anchorLinkStore: anchorLinkStore,
		unmarshal:       json.Unmarshal,
	}
}

func getUniqueDomainCreated(proofs []verifiable.Proof) []verifiable.Proof {
	var (
		set    = make(map[string]struct{})
		result []verifiable.Proof
	)

	for i := range proofs {
		domain, ok := proofs[i]["domain"].(string)
		if !ok {
			continue
		}

		created, ok := proofs[i]["created"].(string)
		if !ok {
			continue
		}

		if _, ok := set[domain+created]; ok {
			continue
		}

		set[domain+created] = struct{}{}
		set[domain+created] = struct{}{}

		result = append(result, proofs[i])
	}

	return result
}

// HandleAnchorEvent handles an anchor event.
// nolint:funlen
func (h *AnchorEventHandler) HandleAnchorEvent(actor, anchorEventRef, source *url.URL,
	anchorEvent *vocab.AnchorEventType) error {
	logger.Debugf("Received request from [%s] for anchor event URL [%s]", actor, anchorEventRef)

	var anchorEventBytes []byte

	if anchorEvent != nil {
		var err error

		anchorEventBytes, err = canonicalizer.MarshalCanonical(anchorEvent)
		if err != nil {
			return fmt.Errorf("marshal anchor event: %w", err)
		}

		// GZIP
	}

	// TODO: Data cannot be provided here because it mixes compressed data CID and uncompressed data

	anchorEventBytes, localHL, err := h.casResolver.Resolve(nil, anchorEventRef.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor event [%s]: %w", anchorEventRef, err)
	}

	// TODO: Data can potentially be uncompressed here and compared to provided data?

	if anchorEvent == nil {
		anchorEvent = &vocab.AnchorEventType{}

		err = h.unmarshal(anchorEventBytes, anchorEvent)
		if err != nil {
			return fmt.Errorf("unmarshal anchor event: %w", err)
		}
	}

	// Make sure that all parents/grandparents of this anchor event are processed.
	err = h.ensureParentAnchorsAreProcessed(anchorEventRef, anchorEvent)
	if err != nil {
		return fmt.Errorf("ensure unprocessed parents are processed for %s: %w", anchorEventRef, err)
	}

	var attributedTo string
	if actor != nil {
		attributedTo = actor.String()
	}

	logger.Infof("Processing anchor event [%s]", anchorEventRef)

	var alternateSources []string

	if source != nil {
		// The anchor index in the AnchorEvent may not be found in the CAS store. This may occur in the event that
		// the anchor origin lost the original data. So we add an alternate source from which the Sidetree
		// files may be retrieved.
		alternateSources = []string{source.String()}
	}

	// Now process the latest anchor event.
	err = h.processAnchorEvent(&anchorInfo{
		anchorEvent: anchorEvent,
		AnchorInfo: &anchorinfo.AnchorInfo{
			Hashlink:         anchorEventRef.String(),
			LocalHashlink:    localHL,
			AttributedTo:     attributedTo,
			AlternateSources: alternateSources,
		},
	})
	if err != nil {
		return fmt.Errorf("process anchor event %s: %w", anchorEventRef, err)
	}

	return nil
}

func (h *AnchorEventHandler) processAnchorEvent(anchorInfo *anchorInfo) error {
	vc, err := util.VerifiableCredentialFromAnchorEvent(anchorInfo.anchorEvent,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor event: %w", err)
	}

	for _, proof := range getUniqueDomainCreated(vc.Proofs) {
		// getUniqueDomainCreated already checked that data is a string
		domain := proof["domain"].(string)   // nolint: errcheck, forcetypeassert
		created := proof["created"].(string) // nolint: errcheck, forcetypeassert

		createdTime, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return fmt.Errorf("parse created: %w", err)
		}

		err = h.monitoringSvc.Watch(vc, time.Now().Add(h.maxDelay), domain, createdTime)
		if err != nil {
			return fmt.Errorf("failed to setup monitoring for anchor credential[%s]: %w", vc.ID, err)
		}
	}

	return h.anchorPublisher.PublishAnchor(anchorInfo.AnchorInfo)
}

// ensureParentAnchorsAreProcessed checks all ancestors (parents, grandparents, etc.) of the given anchor event
// and processes all that have not yet been processed.
func (h *AnchorEventHandler) ensureParentAnchorsAreProcessed(anchorEventRef *url.URL,
	anchorEvent *vocab.AnchorEventType) error {
	unprocessedParents, err := h.getUnprocessedParentAnchorEvents(anchorEventRef.String(), anchorEvent)
	if err != nil {
		return fmt.Errorf("get unprocessed parent anchor events for %s: %w", anchorEventRef, err)
	}

	logger.Debugf("Processing %d parents of anchor event %s: %s",
		len(unprocessedParents), anchorEventRef, unprocessedParents)

	for _, parentAnchorInfo := range unprocessedParents {
		logger.Infof("Processing parent of anchor event [%s]: [%s]",
			anchorEventRef, parentAnchorInfo.Hashlink)

		err = h.processAnchorEvent(parentAnchorInfo)
		if err != nil {
			return fmt.Errorf("process anchor event %s: %w", parentAnchorInfo.Hashlink, err)
		}
	}

	return nil
}

// getUnprocessedParentAnchorEvents returns all unprocessed ancestors (parents, grandparents, etc.) of the given
// anchor event, sorted by oldest to newest.
func (h *AnchorEventHandler) getUnprocessedParentAnchorEvents(
	hl string, anchorEvent *vocab.AnchorEventType) (anchorInfoSlice, error) {
	logger.Debugf("Getting unprocessed parents of anchor event [%s]", hl)

	var unprocessed []*anchorInfo

	for _, parentHL := range anchorEvent.Parent() {
		if containsAnchorEvent(unprocessed, parentHL.String()) {
			logger.Debugf("Not adding parent of anchor event [%s] to the unprocessed list since it has already been added: [%s]",
				hl, parentHL)

			continue
		}

		logger.Debugf("Checking parent of anchor event [%s] to see if it has been processed [%s]", hl, parentHL)

		isProcessed, err := h.isAnchorEventProcessed(parentHL)
		if err != nil {
			return nil, fmt.Errorf("is anchor event processed [%s]: %w", parentHL, err)
		}

		if isProcessed {
			logger.Debugf("Parent of anchor event [%s] was already processed [%s]", hl, parentHL)

			continue
		}

		anchorEventBytes, localHL, err := h.casResolver.Resolve(nil, parentHL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("resolve anchor event [%s]: %w", parentHL, err)
		}

		parentAnchorEvent := &vocab.AnchorEventType{}

		err = h.unmarshal(anchorEventBytes, parentAnchorEvent)
		if err != nil {
			return nil, fmt.Errorf("unmarshal anchor event: %w", err)
		}

		logger.Debugf("Adding parent of anchor event [%s] to the unprocessed list [%s]", hl, parentHL)

		// Add the parent to the head of the list since it needs to be processed first.
		unprocessed = append([]*anchorInfo{
			{
				anchorEvent: parentAnchorEvent,
				AnchorInfo: &anchorinfo.AnchorInfo{
					Hashlink:      parentHL.String(),
					LocalHashlink: localHL,
				},
			},
		}, unprocessed...)

		ancestorAnchorEvents, err := h.getUnprocessedParentAnchorEvents(parentHL.String(), parentAnchorEvent)
		if err != nil {
			return nil, fmt.Errorf("get unprocessed anchor events for parent [%s]: %w", parentHL, err)
		}

		prependAnchorEvents(unprocessed, ancestorAnchorEvents)
	}

	return unprocessed, nil
}

func prependAnchorEvents(existingAnchors, newAnchors []*anchorInfo) {
	for _, anchor := range newAnchors {
		if !containsAnchorEvent(existingAnchors, anchor.Hashlink) {
			// Add the ancestor to the head of the list since it needs to be processed first.
			existingAnchors = append([]*anchorInfo{anchor}, existingAnchors...)
		}
	}
}

func containsAnchorEvent(existingAnchors []*anchorInfo, hl string) bool {
	for _, anchor := range existingAnchors {
		if anchor.Hashlink == hl {
			return true
		}
	}

	return false
}

func (h *AnchorEventHandler) isAnchorEventProcessed(hl *url.URL) (bool, error) {
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
	anchorEvent *vocab.AnchorEventType
}

type anchorInfoSlice []*anchorInfo

func (s anchorInfoSlice) String() string {
	msg := "["

	for i, ai := range s {
		if i > 0 {
			msg += ", "
		}

		msg += ai.Hashlink
	}

	return msg + "]"
}
