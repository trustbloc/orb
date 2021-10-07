/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/hashlink"
)

var logger = log.New("anchorevent")

const (
	multihashPrefix          = "did:orb:uAAA"
	multihashPrefixDelimiter = ":"
)

// BuildAnchorEvent builds an anchor event from the given payload, content object, and verifiable credential.
func BuildAnchorEvent(payload *subject.Payload, contentObj *vocab.ContentObjectType,
	vc *verifiable.Credential) (*vocab.AnchorEventType, error) {
	if len(payload.PreviousAnchors) == 0 {
		return nil, fmt.Errorf("payload is missing previous anchors")
	}

	attributedTo, err := url.Parse(payload.AnchorOrigin)
	if err != nil {
		return nil, fmt.Errorf("parse attributed to URL [%s]: %w", payload.AnchorOrigin, err)
	}

	anchorObjectURL, err := computeHashlinkOfContentObject(contentObj)
	if err != nil {
		return nil, fmt.Errorf("get hashlink of content object: %w", err)
	}

	bytes, err := vc.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal anchor credential: %w", err)
	}

	witness, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc(bytes))
	if err != nil {
		return nil, fmt.Errorf("create new object with document: %w", err)
	}

	return vocab.NewAnchorEvent(
		vocab.WithAttributedTo(attributedTo),
		vocab.WithAnchors(anchorObjectURL),
		vocab.WithPublishedTime(payload.Published),
		vocab.WithParent(resolveParents(payload)...),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(vocab.NewAnchorObject(
			contentObj,
			witness,
			vocab.WithURL(anchorObjectURL),
		)))),
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

// BuildContentObject builds a ContentObject from the given payload.
func BuildContentObject(payload *subject.Payload) (*vocab.ContentObjectType, error) {
	gen, err := generator.CreateGenerator(payload.Namespace, payload.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create generator: %w", err)
	}

	if len(payload.PreviousAnchors) == 0 {
		return nil, fmt.Errorf("payload is missing previous anchors")
	}

	var resources []*vocab.Resource

	for key, value := range payload.PreviousAnchors {
		resourceID := fmt.Sprintf("%s:%s", multihashPrefix, key)

		var resource *vocab.Resource

		if value == "" {
			resource = vocab.NewResource(resourceID, "")
		} else {
			pos := strings.LastIndex(value, ":")
			if pos == -1 {
				return nil, fmt.Errorf("invalid previous anchor hashlink[%s] - must contain separator ':'", value)
			}

			previousAnchorKey := value[:pos]

			resource = vocab.NewResource(resourceID, previousAnchorKey)
		}

		resources = append(resources, resource)
	}

	coreIndexURL, err := url.Parse(payload.CoreIndex)
	if err != nil {
		return nil, fmt.Errorf("parse core index URL [%s]: %w", payload.AnchorOrigin, err)
	}

	return vocab.NewContentObject(gen, coreIndexURL, resources...), nil
}

func computeHashlinkOfContentObject(contentObj *vocab.ContentObjectType) (*url.URL, error) {
	contentBytes, err := canonicalizer.MarshalCanonical(contentObj)
	if err != nil {
		return nil, fmt.Errorf("marshal content cobject: %w", err)
	}

	hl, err := hashlink.New().CreateHashLink(contentBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("create hashlink of content cobject: %w", err)
	}

	hlURL, err := url.Parse(hl)
	if err != nil {
		return nil, fmt.Errorf("parse hashlink of content cobject: %w", err)
	}

	return hlURL, nil
}

// GetPayloadFromAnchorEvent populates a Payload from the given anchor event.
func GetPayloadFromAnchorEvent(anchorEvent *vocab.AnchorEventType) (*subject.Payload, error) {
	if len(anchorEvent.Attachment()) == 0 {
		return nil, fmt.Errorf("anchor event is missing attachment")
	}

	contentObj := anchorEvent.ContentObject()

	ns, ver, err := generator.ParseNamespaceAndVersion(contentObj.Generator())
	if err != nil {
		return nil, fmt.Errorf("failed to parse namespace and version from anchor event generator: %w", err)
	}

	if contentObj.Subject == nil {
		return nil, fmt.Errorf("anchor event content object is missing subject")
	}

	resources := contentObj.Resources()

	operationCount := uint64(len(resources))

	prevAnchors, err := getPreviousAnchors(resources, anchorEvent.Parent())
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous anchors from anchorEvent: %w", err)
	}

	payload := &subject.Payload{
		Namespace:       ns,
		Version:         ver,
		CoreIndex:       contentObj.Subject.String(),
		OperationCount:  operationCount,
		PreviousAnchors: prevAnchors,
		AnchorOrigin:    anchorEvent.AttributedTo().String(),
		Published:       anchorEvent.Published(),
	}

	return payload, nil
}

func getPreviousAnchors(resources []*vocab.Resource, previous []*url.URL) (map[string]string, error) {
	previousAnchors := make(map[string]string)

	for _, res := range resources {
		suffix, err := removeMultihashPrefix(res.ID)
		if err != nil {
			return nil, err
		}

		var prevAnchor string

		if res.PreviousAnchor != "" {
			suffix, prevAnchor, err = getPreviousAnchorForResource(suffix, res.PreviousAnchor, previous)
			if err != nil {
				return nil, fmt.Errorf("get previous anchor for resource: %w", err)
			}
		}

		logger.Debugf("Adding previous anchor for suffix [%s]: [%s]", suffix, prevAnchor)

		previousAnchors[suffix] = prevAnchor
	}

	return previousAnchors, nil
}

func getPreviousAnchorForResource(suffix, res string, previous []*url.URL) (string, string, error) {
	for _, prev := range previous {
		if !strings.HasPrefix(prev.String(), res) {
			continue
		}

		logger.Debugf("Found previous anchor [%s] for suffix [%s]", prev, suffix)

		return suffix, prev.String(), nil
	}

	return "", "", fmt.Errorf("resource[%s] not found in previous anchor list", res)
}

func removeMultihashPrefix(id string) (string, error) {
	prefix := multihashPrefix + multihashPrefixDelimiter

	if !strings.HasPrefix(id, prefix) {
		return "", fmt.Errorf("id has to start with %s", prefix)
	}

	return id[len(prefix):], nil
}

func contains(arr []string, v string) bool {
	for _, a := range arr {
		if a == v {
			return true
		}
	}

	return false
}
