/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbgenerator

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/document/util"
)

var logger = log.New("anchorevent")

const (
	// ID specifies the ID of the generator.
	ID = "https://w3id.org/orb#v0"

	// Namespace specifies the namespace of the generator.
	Namespace = "did:orb"

	// Version specifies the version of the generator.
	Version = uint64(0)

	multihashPrefix  = "did:orb"
	unpublishedLabel = "uAAA"

	separator     = ":"
	hashlinkParts = 3
)

// Generator generates a content object for did:orb anchor events.
type Generator struct {
	*options
}

// Opt defines an option for the generator.
type Opt func(opts *options)

type options struct {
	id        string
	namespace string
	version   uint64
}

// WithNamespace sets the namespace of the generator.
func WithNamespace(ns string) Opt {
	return func(opts *options) {
		opts.namespace = ns
	}
}

// WithVersion sets the version of the generator.
func WithVersion(version uint64) Opt {
	return func(opts *options) {
		opts.version = version
	}
}

// WithID sets the ID of the generator.
func WithID(id string) Opt {
	return func(opts *options) {
		opts.id = id
	}
}

// New returns a new generator.
func New(opts ...Opt) *Generator {
	optns := &options{
		id:        ID,
		namespace: Namespace,
		version:   Version,
	}

	for _, opt := range opts {
		opt(optns)
	}

	return &Generator{
		options: optns,
	}
}

// ID returns the ID of the generator.
func (g *Generator) ID() string {
	return g.id
}

// Namespace returns the Namespace for the DID method.
func (g *Generator) Namespace() string {
	return g.namespace
}

// Version returns the Version of this generator.
func (g *Generator) Version() uint64 {
	return g.version
}

// CreateContentObject creates a content object from the given payload.
func (g *Generator) CreateContentObject(payload *subject.Payload) (vocab.Document, error) {
	if payload.CoreIndex == "" {
		return nil, fmt.Errorf("payload is missing core index")
	}

	if len(payload.PreviousAnchors) == 0 {
		return nil, fmt.Errorf("payload is missing previous anchors")
	}

	var resources []*resource

	for _, value := range payload.PreviousAnchors {
		logger.Debugf("RESOURCE - Key [%s] Value [%s]", value.Suffix, value.Anchor)

		var res *resource

		if value.Anchor == "" {
			res = &resource{ID: fmt.Sprintf("%s:%s:%s", multihashPrefix, unpublishedLabel, value.Suffix)}
		} else {
			parts := strings.Split(value.Anchor, separator)

			if len(parts) != hashlinkParts {
				return nil, fmt.Errorf("invalid number of parts for previous anchor hashlink[%s] for suffix[%s]: expected 3, got %d", value, value.Suffix, len(parts)) //nolint:lll
			}

			pos := strings.LastIndex(value.Anchor, ":")
			if pos == -1 {
				return nil, fmt.Errorf("invalid previous anchor hashlink[%s] - must contain separator ':'", value)
			}

			prevAnchor := parts[0] + separator + parts[1]

			res = &resource{ID: fmt.Sprintf("%s:%s:%s", multihashPrefix, parts[1], value.Suffix), PreviousAnchor: prevAnchor}
		}

		resources = append(resources, res)
	}

	contentObj := &contentObject{
		Subject: payload.CoreIndex,
		Properties: &propertiesType{
			Generator: g.id,
			Resources: resources,
		},
	}

	contentObjDoc, err := vocab.MarshalToDoc(contentObj)
	if err != nil {
		return nil, fmt.Errorf("marshal content object to document: %w", err)
	}

	return contentObjDoc, nil
}

// CreatePayload creates a payload from the given anchor event.
func (g *Generator) CreatePayload(anchorEvent *vocab.AnchorEventType) (*subject.Payload, error) {
	anchorObj, err := anchorEvent.AnchorObject(anchorEvent.Anchors())
	if err != nil {
		return nil, fmt.Errorf("anchor object for [%s]: %w", anchorEvent.Anchors(), err)
	}

	contentObj := &contentObject{}

	err = anchorObj.ContentObject().Unmarshal(contentObj)
	if err != nil {
		return nil, fmt.Errorf("unmarshal content object: %w", err)
	}

	if contentObj.Subject == "" {
		return nil, fmt.Errorf("content object is missing subject")
	}

	resources := contentObj.Resources()

	operationCount := uint64(len(resources))

	prevAnchors, err := g.getPreviousAnchors(resources, anchorEvent.Parent())
	if err != nil {
		return nil, fmt.Errorf("failed to parse previous anchors from anchorEvent: %w", err)
	}

	return &subject.Payload{
		Namespace:       g.namespace,
		Version:         g.version,
		CoreIndex:       contentObj.Subject,
		OperationCount:  operationCount,
		PreviousAnchors: prevAnchors,
		AnchorOrigin:    anchorEvent.AttributedTo().String(),
		Published:       anchorEvent.Published(),
	}, nil
}

func (g *Generator) getPreviousAnchors(resources []*resource, previous []*url.URL) ([]*subject.SuffixAnchor, error) {
	var previousAnchors []*subject.SuffixAnchor

	for _, res := range resources {
		suffix, err := util.GetSuffix(res.ID)
		if err != nil {
			return nil, err
		}

		prevAnchor := &subject.SuffixAnchor{Suffix: suffix}

		if res.PreviousAnchor != "" {
			prevAnchor, err = getPreviousAnchorForResource(suffix, res.PreviousAnchor, previous)
			if err != nil {
				return nil, fmt.Errorf("get previous anchor for resource: %w", err)
			}
		}

		previousAnchors = append(previousAnchors, prevAnchor)
	}

	return previousAnchors, nil
}

type propertiesType struct {
	Generator string      `json:"https://w3id.org/activityanchors#generator,omitempty"`
	Resources []*resource `json:"https://w3id.org/activityanchors#resources,omitempty"`
}

type resource struct {
	ID             string `json:"ID"`
	PreviousAnchor string `json:"previousAnchor,omitempty"`
}

type contentObject struct {
	Subject    string          `json:"subject,omitempty"`
	Properties *propertiesType `json:"properties,omitempty"`
}

func (t *contentObject) Resources() []*resource {
	if t == nil || t.Properties == nil {
		return nil
	}

	return t.Properties.Resources
}

func getPreviousAnchorForResource(suffix, res string, previous []*url.URL) (*subject.SuffixAnchor, error) {
	for _, prev := range previous {
		if !strings.HasPrefix(prev.String(), res) {
			continue
		}

		logger.Debugf("Found previous anchor [%s] for suffix [%s]", prev, suffix)

		return &subject.SuffixAnchor{Suffix: suffix, Anchor: prev.String()}, nil
	}

	return nil, fmt.Errorf("resource[%s] not found in previous anchor list", res)
}
