/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activity

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"

	"github.com/trustbloc/orb/pkg/anchor/activity/generator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
)

const (
	multihashPrefix          = "urn:multihash"
	multihashPrefixDelimiter = ":"

	anchorEventType    = "AnchorEvent"
	anchorIndexType    = "AnchorIndex"
	anchorResourceType = "AnchorResource"

	linkType = "Link"

	idKey             = "id"
	previousAnchorKey = "previousAnchor"
	resourceTypeKey   = "type"
)

// Activity defines anchor activity.
type Activity struct {
	Context      interface{}                    `json:"@context,omitempty"`
	Type         string                         `json:"type,omitempty"`
	AttributedTo string                         `json:"attributedTo,omitempty"`
	Published    *util.TimeWithTrailingZeroMsec `json:"published,omitempty"`
	Previous     []Reference                    `json:"previous,omitempty"`
	Attachment   []Attachment                   `json:"attachment,omitempty"`
}

// Attachment defines anchor activity attachment.
type Attachment struct {
	Type      string        `json:"type,omitempty"`
	Generator string        `json:"generator,omitempty"`
	URL       []Link        `json:"url,omitempty"`
	Resources []interface{} `json:"resources,omitempty"`
}

// Reference defines anchor activity reference.
type Reference struct {
	ID   string `json:"id,omitempty"`
	URL  string `json:"url,omitempty"`
	Type string `json:"type,omitempty"`
}

// Link defines link.
type Link struct {
	Href string `json:"href,omitempty"`
	Type string `json:"type,omitempty"`
	Rel  string `json:"rel,omitempty"`
}

// Resource defines resource.
type Resource struct {
	ID             string `json:"id,omitempty"`
	PreviousAnchor string `json:"previousAnchor,omitempty"`
	Type           string `json:"type,omitempty"`
}

// BuildActivityFromPayload builds activity from payload.
func BuildActivityFromPayload(payload *subject.Payload) (*Activity, error) {
	gen, err := generator.CreateGenerator(payload.Namespace, payload.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to create generator: %w", err)
	}

	if len(payload.PreviousAnchors) == 0 {
		return nil, fmt.Errorf("payload is missing previous anchors")
	}

	var resources []interface{}

	var previous []Reference

	for key, value := range payload.PreviousAnchors {
		resourceID := fmt.Sprintf("%s:%s", multihashPrefix, key)

		if value == "" {
			resources = append(resources, resourceID)
		} else {
			resourceID := fmt.Sprintf("%s:%s", multihashPrefix, key)
			previousAnchorID := fmt.Sprintf("%s:%s", multihashPrefix, value)
			previous = append(previous, Reference{ID: previousAnchorID, URL: value, Type: linkType})
			resources = append(resources, Resource{ID: resourceID, PreviousAnchor: previousAnchorID, Type: anchorResourceType})
		}
	}

	attachment := []Attachment{{
		Type:      anchorIndexType,
		Generator: gen,
		URL:       []Link{{Href: payload.CoreIndex, Type: linkType, Rel: "self"}},
		Resources: resources,
	}}

	return &Activity{
		Type:         anchorEventType,
		AttributedTo: payload.AnchorOrigin,
		Published:    payload.Published,
		Previous:     previous,
		Attachment:   attachment,
	}, nil
}

// GetPayloadFromActivity gets payload from activity.
func GetPayloadFromActivity(activity *Activity) (*subject.Payload, error) {
	if len(activity.Attachment) == 0 {
		return nil, fmt.Errorf("activity is missing attachment")
	}

	// for now we have one attachment only
	attach := activity.Attachment[0]

	ns, ver, err := generator.ParseNamespaceAndVersion(attach.Generator)
	if err != nil {
		return nil, fmt.Errorf("failed to parse namespace and version from activity generator: %w", err)
	}

	if len(attach.URL) == 0 {
		return nil, fmt.Errorf("activity is missing attachment URL")
	}

	// TODO: add support for alternates (sidetree-core doesn't support multiple sources)
	coreIndex := attach.URL[0].Href

	operatinCount := uint64(len(attach.Resources))

	prevAnchors, err := getPreviousAnchors(attach.Resources, activity.Previous)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous anchors from activity: %w", err)
	}

	payload := &subject.Payload{
		Namespace:       ns,
		Version:         ver,
		CoreIndex:       coreIndex,
		OperationCount:  operatinCount,
		PreviousAnchors: prevAnchors,
		AnchorOrigin:    activity.AttributedTo,
		Published:       activity.Published,
	}

	return payload, nil
}

func getPreviousAnchors(resources []interface{}, previous []Reference) (map[string]string, error) {
	previousAnchors := make(map[string]string)

	for _, resObj := range resources {
		switch res := resObj.(type) {
		case string:
			suffix, err := removeMultihashPrefix(res)
			if err != nil {
				return nil, err
			}

			previousAnchors[suffix] = ""

		case map[string]interface{}:
			resObj, err := getResourceFromMap(res)
			if err != nil {
				return nil, fmt.Errorf("failed to get resource from map: %w", err)
			}

			suffix, prevAnchor, err := getPreviousAnchorForResource(resObj, previous)
			if err != nil {
				return nil, err
			}

			previousAnchors[suffix] = prevAnchor

		default:
			return nil, fmt.Errorf("unexpected object type '%T' for resource", resObj)
		}
	}

	return previousAnchors, nil
}

func getResourceFromMap(m map[string]interface{}) (*Resource, error) {
	id, err := getStringFromMap(idKey, m)
	if err != nil {
		return nil, err
	}

	prevAnchor, err := getStringFromMap(previousAnchorKey, m)
	if err != nil {
		return nil, err
	}

	resourceType, err := getStringFromMap(resourceTypeKey, m)
	if err != nil {
		return nil, err
	}

	return &Resource{ID: id, PreviousAnchor: prevAnchor, Type: resourceType}, nil
}

func getStringFromMap(key string, m map[string]interface{}) (string, error) {
	valObj, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing value for key[%s]", key)
	}

	val, ok := valObj.(string)
	if !ok {
		return "", fmt.Errorf("value[%T] for key[%s] is not a string", valObj, key)
	}

	return val, nil
}

func getPreviousAnchorForResource(res *Resource, previous []Reference) (string, string, error) {
	for _, prev := range previous {
		if res.PreviousAnchor == prev.ID {
			suffix, err := removeMultihashPrefix(res.ID)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse previous anchors from activity: %w", err)
			}

			return suffix, prev.URL, nil
		}
	}

	return "", "", fmt.Errorf("resource ID[%s] not found in previous links", res.ID)
}

func removeMultihashPrefix(id string) (string, error) {
	prefix := multihashPrefix + multihashPrefixDelimiter

	if !strings.HasPrefix(id, prefix) {
		return "", fmt.Errorf("id has to start with %s", prefix)
	}

	return id[len(prefix):], nil
}
