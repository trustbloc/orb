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
	"github.com/trustbloc/orb/pkg/linkset"
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
// nolint:funlen,gocyclo,cyclop
func (h *AnchorEventHandler) HandleAnchorEvent(actor, anchorRef, source *url.URL,
	anchorEvent *vocab.AnchorEventType) error {
	logger.Debugf("Received request from [%s] for anchor [%s]", actor, anchorRef)

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

	logger.Infof("Processing anchor [%s]", anchorRef)

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
	vc, err := util.VerifiableCredentialFromAnchorLink(anchorInfo.anchorLink,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor link: %w", err)
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
			// This shouldn't be a fatal error since the anchor being processed may have multiple
			// witness proofs and, if one of the witness domains is down, it should not prevent the
			// anchor from being processed.
			logger.Errorf("Failed to setup monitoring for anchor credential[%s]: %w", vc.ID, err)
		}
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

	logger.Debugf("Processing %d parents of anchor [%s]: %s",
		len(unprocessedParents), anchorRef, unprocessedParents)

	for _, parentAnchorInfo := range unprocessedParents {
		logger.Infof("Processing parent of anchor [%s]: [%s]", anchorRef, parentAnchorInfo.Hashlink)

		err = h.processAnchorEvent(parentAnchorInfo)
		if err != nil {
			return fmt.Errorf("process anchor [%s]: %w", parentAnchorInfo.Hashlink, err)
		}
	}

	return nil
}

// getUnprocessedParentAnchors returns all unprocessed ancestors (parents, grandparents, etc.) of the given
// anchor event, sorted by oldest to newest.
//nolint:gocyclo,cyclop
func (h *AnchorEventHandler) getUnprocessedParentAnchors(hl string, anchorLink *linkset.Link) (anchorInfoSlice, error) {
	logger.Debugf("Getting unprocessed parents of anchor [%s]", hl)

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
			logger.Debugf("Not adding parent of anchor [%s] to the unprocessed list since it has already been added: [%s]",
				hl, parentHL)

			continue
		}

		info, err := h.getUnprocessedParentAnchor(hl, parentHL)
		if err != nil {
			return nil, err
		}

		if info == nil {
			continue
		}

		logger.Debugf("Adding parent of anchor event [%s] to the unprocessed list [%s]", hl, parentHL)

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

func (h *AnchorEventHandler) getUnprocessedParentAnchor(hl string, parentHL *url.URL) (*anchorInfo, error) {
	logger.Debugf("Checking parent of anchor [%s] to see if it has been processed [%s]", hl, parentHL)

	isProcessed, err := h.isAnchorProcessed(parentHL)
	if err != nil {
		return nil, fmt.Errorf("is anchor processed [%s]: %w", parentHL, err)
	}

	if isProcessed {
		logger.Debugf("Parent of anchor [%s] was already processed [%s]", hl, parentHL)

		return nil, nil
	}

	anchorLinksetBytes, localHL, err := h.casResolver.Resolve(nil, parentHL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("resolve anchor [%s]: %w", parentHL, err)
	}

	parentAnchorLinkset := &linkset.Linkset{}

	err = h.unmarshal(anchorLinksetBytes, parentAnchorLinkset)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor Linkset: %w", err)
	}

	parentAnchorLink := parentAnchorLinkset.Link()

	if parentAnchorLink == nil {
		return nil, fmt.Errorf("parent Linkset [%s] is empty", parentHL)
	}

	return &anchorInfo{
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
