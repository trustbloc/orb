/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
)

var logger = log.New("anchorevent")

// TODO: Remove this global and move the global functions below to an "anchor event builder".
var registry = generator.NewRegistry() //nolint:gochecknoglobals

// ContentObject wraps a content object payload and includes the ID of the generator used to generate the payload.
type ContentObject struct {
	GeneratorID string
	Payload     vocab.Document
}

// BuildAnchorEvent builds an anchor event from the given payload, content object, and verifiable credential.
func BuildAnchorEvent(payload *subject.Payload, gen string,
	indexContentObj, witnessContentObj vocab.Document) (*vocab.AnchorEventType, error) {
	attributedTo, err := url.Parse(payload.AnchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("parse attributed to URL [%s]: %w", payload.AnchorOrigin, err)
	}

	witnessAnchorObj, err := vocab.NewAnchorObject(gen, witnessContentObj)
	if err != nil {
		return nil, fmt.Errorf("create new witness anchor object: %w", err)
	}

	indexAnchorObj, err := vocab.NewAnchorObject(gen, indexContentObj,
		vocab.WithLink(vocab.NewLink(witnessAnchorObj.URL()[0], vocab.RelationshipWitness)))
	if err != nil {
		return nil, fmt.Errorf("create new index anchor object: %w", err)
	}

	return vocab.NewAnchorEvent(
		vocab.WithAttributedTo(attributedTo),
		vocab.WithAnchors(indexAnchorObj.URL()[0]),
		vocab.WithPublishedTime(payload.Published),
		vocab.WithParent(resolveParents(payload)...),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(witnessAnchorObj))),
	), nil
}

func resolveParents(payload *subject.Payload) []*url.URL {
	var previous []string

	for _, value := range payload.PreviousAnchors {
		if value.Anchor != "" {
			if !contains(previous, value.Anchor) {
				previous = append(previous, value.Anchor)
			}
		}
	}

	parents := make([]*url.URL, len(previous))

	for i, p := range previous {
		parent, err := url.Parse(p)
		if err != nil {
			logger.Warnf("Invalid parent URL [%s]: %s", p, err)
		}

		parents[i] = parent
	}

	return parents
}

// BuildContentObject builds a contentObject from the given payload.
func BuildContentObject(payload *subject.Payload) (*ContentObject, error) {
	gen, err := registry.GetByNamespaceAndVersion(payload.Namespace, payload.Version)
	if err != nil {
		return nil, err
	}

	contentObjDoc, err := gen.CreateContentObject(payload)
	if err != nil {
		return nil, fmt.Errorf("create content object: %w", err)
	}

	return &ContentObject{
		GeneratorID: gen.ID(),
		Payload:     contentObjDoc,
	}, nil
}

// GetPayloadFromAnchorEvent populates a Payload from the given anchor event.
func GetPayloadFromAnchorEvent(anchorEvent *vocab.AnchorEventType) (*subject.Payload, error) {
	anchorObj, err := anchorEvent.AnchorObject(anchorEvent.Index())
	if err != nil {
		return nil, fmt.Errorf("anchor object for [%s]: %w", anchorEvent.Index(), err)
	}

	gen, err := registry.Get(anchorObj.Generator())
	if err != nil {
		return nil, fmt.Errorf("get generator: %w", err)
	}

	payload, err := gen.CreatePayload(anchorEvent)
	if err != nil {
		return nil, fmt.Errorf("get payload from anchor event: %w", err)
	}

	return payload, nil
}

func contains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
}
