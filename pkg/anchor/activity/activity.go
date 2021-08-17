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
	multihashPrefix          = "did:orb:uAAA"
	multihashPrefixDelimiter = ":"

	anchorEventType    = "AnchorEvent"
	anchorIndexType    = "AnchorIndex"
	anchorObjectType   = "AnchorObject"
	anchorResourceType = "AnchorResource"

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
	Parent       []string                       `json:"parent,omitempty"`
	Attachment   []Attachment                   `json:"attachment,omitempty"`
}

// Attachment defines anchor activity attachment.
type Attachment struct {
	Type      string        `json:"type,omitempty"`
	Generator string        `json:"generator,omitempty"`
	URL       string        `json:"url,omitempty"`
	Resources []interface{} `json:"resources,omitempty"`
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

	var previous []string

	for key, value := range payload.PreviousAnchors {
		resourceID := fmt.Sprintf("%s:%s", multihashPrefix, key)

		if value == "" {
			resources = append(resources, resourceID)
		} else {
			if !contains(previous, value) {
				previous = append(previous, value)
			}

			pos := strings.LastIndex(value, ":")
			if pos == -1 {
				return nil, fmt.Errorf("invalid previous anchor hashlink[%s] - must contain separator ':'", value)
			}

			previousAnchorKey := value[:pos]
			resources = append(resources, Resource{ID: resourceID, PreviousAnchor: previousAnchorKey, Type: anchorResourceType})
		}
	}

	attachments := []Attachment{{
		Type:      anchorIndexType,
		Generator: gen,
		URL:       payload.CoreIndex,
		Resources: resources,
	}}

	for _, attach := range payload.Attachments {
		if attach != payload.CoreIndex {
			attachments = append(attachments, Attachment{Type: anchorObjectType, URL: attach})
		}
	}

	return &Activity{
		Type:         anchorEventType,
		AttributedTo: payload.AnchorOrigin,
		Published:    payload.Published,
		Parent:       previous,
		Attachment:   attachments,
	}, nil
}

// GetPayloadFromActivity gets payload from activity.
func GetPayloadFromActivity(activity *Activity) (*subject.Payload, error) {
	if len(activity.Attachment) == 0 {
		return nil, fmt.Errorf("activity is missing attachment")
	}

	anchorIndex, err := getAnchorIndex(activity.Attachment)
	if err != nil {
		return nil, err
	}

	ns, ver, err := generator.ParseNamespaceAndVersion(anchorIndex.Generator)
	if err != nil {
		return nil, fmt.Errorf("failed to parse namespace and version from activity generator: %w", err)
	}

	if anchorIndex.URL == "" {
		return nil, fmt.Errorf("anchor index is missing URL")
	}

	operationCount := uint64(len(anchorIndex.Resources))

	prevAnchors, err := getPreviousAnchors(anchorIndex.Resources, activity.Parent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous anchors from activity: %w", err)
	}

	payload := &subject.Payload{
		Namespace:       ns,
		Version:         ver,
		CoreIndex:       anchorIndex.URL,
		OperationCount:  operationCount,
		PreviousAnchors: prevAnchors,
		Attachments:     getAnchorObjects(activity.Attachment),
		AnchorOrigin:    activity.AttributedTo,
		Published:       activity.Published,
	}

	return payload, nil
}

func getAnchorIndex(attachments []Attachment) (Attachment, error) {
	for _, attach := range attachments {
		if attach.Type == anchorIndexType {
			return attach, nil
		}
	}

	return Attachment{}, fmt.Errorf("anchor index not found")
}

func getAnchorObjects(attachments []Attachment) []string {
	var anchorObjects []string

	for _, attach := range attachments {
		if attach.Type == anchorObjectType {
			anchorObjects = append(anchorObjects, attach.URL)
		}
	}

	return anchorObjects
}

func getPreviousAnchors(resources []interface{}, previous []string) (map[string]string, error) {
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

func getPreviousAnchorForResource(res *Resource, previous []string) (string, string, error) {
	for _, prev := range previous {
		if strings.HasPrefix(prev, res.PreviousAnchor) {
			suffix, err := removeMultihashPrefix(res.ID)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse previous anchors from activity: %w", err)
			}

			return suffix, prev, nil
		}
	}

	return "", "", fmt.Errorf("resource[%s] not found in previous anchor list", res.PreviousAnchor)
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
