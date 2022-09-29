/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acknowlegement

import (
	"fmt"
	"net/url"

	"go.uber.org/zap"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/hashlink"
)

var logger = log.NewStructured("anchor-acknowledgement-handler")

type anchorLinkStore interface {
	PutLinks(links []*url.URL) error
	DeleteLinks(links []*url.URL) error
}

// Handler handles notifications of successful anchor events processed from an Orb server.
type Handler struct {
	anchorLinkStore anchorLinkStore
}

// New returns a new handler.
func New(store anchorLinkStore) *Handler {
	return &Handler{anchorLinkStore: store}
}

// AnchorEventAcknowledged handles a notification of a successful anchor event processed from an Orb server.
// The given additional references are added to the anchor link store so that they are included in WebFinger responses.
func (p *Handler) AnchorEventAcknowledged(actor, anchorRef *url.URL, additionalAnchorRefs []*url.URL) error {
	logger.Info("Anchor event was acknowledged.", log.WithActorIRI(actor),
		log.WithHashlink(hashlink.ToString(anchorRef)),
		zap.String("additional-anchors", hashlink.ToString(additionalAnchorRefs...)))

	links, err := getLinks(anchorRef, additionalAnchorRefs)
	if err != nil {
		return fmt.Errorf("get links: %w", err)
	}

	if err := p.anchorLinkStore.PutLinks(links); err != nil {
		return fmt.Errorf("put links: %w", err)
	}

	return nil
}

// UndoAnchorEventAcknowledgement handles a notification that the previous acknowledgement of an anchor
// event was undone. The given additional references are removed from the anchor link store so that they
// are no longer included in WebFinger responses.
func (p *Handler) UndoAnchorEventAcknowledgement(actor, anchorRef *url.URL, additionalAnchorRefs []*url.URL) error {
	logger.Info("Anchor event acknowledgement was undone.", log.WithActorIRI(actor),
		log.WithHashlink(hashlink.ToString(anchorRef)),
		zap.String("additional-anchors", hashlink.ToString(additionalAnchorRefs...)))

	links, err := getLinks(anchorRef, additionalAnchorRefs)
	if err != nil {
		return fmt.Errorf("get links: %w", err)
	}

	if err := p.anchorLinkStore.DeleteLinks(links); err != nil {
		return fmt.Errorf("delete links: %w", err)
	}

	return nil
}

func getLinks(anchorRef *url.URL, additionalAnchorRefs []*url.URL) ([]*url.URL, error) {
	parser := hashlink.New()

	info, err := parser.ParseHashLink(anchorRef.String())
	if err != nil {
		return nil, fmt.Errorf("parse hashlink [%s]: %w", anchorRef, err)
	}

	var links []*url.URL

	for _, hl := range additionalAnchorRefs {
		hlInfo, err := parser.ParseHashLink(hl.String())
		if err != nil {
			logger.Warn("Error parsing hashlink", log.WithHashlinkURI(hl), log.WithError(err))

			continue
		}

		if hlInfo.ResourceHash != info.ResourceHash {
			logger.Warn("Hash in additional anchor does not match the hash of the acknowledged anchor event",
				zap.String("additional-anchor-hash", hlInfo.ResourceHash),
				zap.String("anchor-event-hash", info.ResourceHash))

			continue
		}

		links = append(links, hl)
	}

	return links, nil
}
