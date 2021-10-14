/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
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
func BuildAnchorEvent(payload *subject.Payload, contentObj *ContentObject,
	vc *verifiable.Credential) (*vocab.AnchorEventType, error) {
	attributedTo, err := url.Parse(payload.AnchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("parse attributed to URL [%s]: %w", payload.AnchorOrigin, err)
	}

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal anchor credential: %w", err)
	}

	witness, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return nil, fmt.Errorf("create new object with document: %w", err)
	}

	anchorObj, err := vocab.NewAnchorObject(contentObj.GeneratorID, contentObj.Payload, witness)
	if err != nil {
		return nil, fmt.Errorf("create new anchor object: %w", err)
	}

	return vocab.NewAnchorEvent(
		vocab.WithAttributedTo(attributedTo),
		vocab.WithAnchors(anchorObj.URL()[0]),
		vocab.WithPublishedTime(payload.Published),
		vocab.WithParent(resolveParents(payload)...),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(anchorObj))),
	), nil
}

func resolveParents(payload *subject.Payload) []*url.URL {
	var previous []string

	for _, value := range payload.PreviousAnchors {
		if value != "" {
			if !contains(previous, value) {
				previous = append(previous, value)
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
	anchorObj, err := anchorEvent.AnchorObject(anchorEvent.Anchors())
	if err != nil {
		return nil, fmt.Errorf("anchor object for [%s]: %w", anchorEvent.Anchors(), err)
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
