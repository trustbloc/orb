/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorlinkset

import (
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/linkset"
)

var logger = log.NewStructured("anchorevent")

// Builder constructs an anchor linkset.
type Builder struct {
	registry generatorRegistry
}

// NewBuilder returns a new anchor linkset builder.
func NewBuilder(registry generatorRegistry) *Builder {
	return &Builder{registry: registry}
}

// ContentObject wraps a content object payload and includes the ID of the generator used to generate the payload.
type ContentObject struct {
	Profile *url.URL
	Payload vocab.Document
}

// VCBuilder constructs a verifiable credential.
type VCBuilder func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error)

type generatorRegistry interface {
	Get(id *url.URL) (generator.Generator, error)
	GetByNamespaceAndVersion(ns string, ver uint64) (generator.Generator, error)
}

// BuildAnchorLink builds an anchor Link from the given payload.
//nolint:funlen,gocyclo,cyclop
func (b *Builder) BuildAnchorLink(payload *subject.Payload, dataURIMediaType datauri.MediaType,
	buildVC VCBuilder) (anchorLink *linkset.Link, vcBytes []byte, err error) {
	contentObj, err := b.buildContentObject(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("build content object: %w", err)
	}

	originalBytes, err := canonicalizer.MarshalCanonical(contentObj.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal content object: %w", err)
	}

	anchorURI, originalRef, err := linkset.NewAnchorRef(originalBytes, dataURIMediaType, linkset.TypeLinkset)
	if err != nil {
		return nil, nil, fmt.Errorf("build 'original' reference: %w", err)
	}

	coreIndexInfo, err := hashlink.New().ParseHashLink(payload.CoreIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("parse core index hashlink [%s]: %w", payload.CoreIndex, err)
	}

	vc, err := buildVC(anchorURI.String(), hashlink.HLPrefix+coreIndexInfo.ResourceHash)
	if err != nil {
		return nil, nil, fmt.Errorf("build anchor credential: %w", err)
	}

	vcBytes, err = canonicalizer.MarshalCanonical(vc)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal verifiable credential: %w", err)
	}

	repliesDataURI, err := datauri.New(vcBytes, dataURIMediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("create 'replies' data URI: %w", err)
	}

	coreIndexURI, err := url.Parse(payload.CoreIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("parse core index URI [%s]: %w", payload.CoreIndex, err)
	}

	relatedLinkset := linkset.New(
		linkset.NewRelatedLink(
			anchorURI, contentObj.Profile, coreIndexURI,
			resolveParents(payload.PreviousAnchors)...,
		),
	)

	relatedDataURI, err := datauri.MarshalCanonical(relatedLinkset, dataURIMediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("create related Linkset data URI: %w", err)
	}

	authorURI, err := url.Parse(payload.AnchorOrigin)
	if err != nil {
		return nil, nil, fmt.Errorf("parse anchor origin URI [%s]: %w", payload.AnchorOrigin, err)
	}

	anchorLink = linkset.NewLink(anchorURI, authorURI, contentObj.Profile, originalRef,
		linkset.NewReference(relatedDataURI, linkset.TypeLinkset),
		linkset.NewReference(repliesDataURI, linkset.TypeJSONLD),
	)

	return anchorLink, vcBytes, nil
}

func (b *Builder) buildContentObject(payload *subject.Payload) (*ContentObject, error) {
	gen, err := b.registry.GetByNamespaceAndVersion(payload.Namespace, payload.Version)
	if err != nil {
		return nil, err
	}

	contentObjDoc, err := gen.CreateContentObject(payload)
	if err != nil {
		return nil, fmt.Errorf("create content object: %w", err)
	}

	return &ContentObject{
		Profile: gen.ID(),
		Payload: contentObjDoc,
	}, nil
}

// GetPayloadFromAnchorLink populates a Payload from the given anchor event.
func (b *Builder) GetPayloadFromAnchorLink(anchorLink *linkset.Link) (*subject.Payload, error) {
	gen, err := b.registry.Get(anchorLink.Profile())
	if err != nil {
		return nil, fmt.Errorf("get generator: %w", err)
	}

	contentBytes, err := anchorLink.Original().Content()
	if err != nil {
		return nil, fmt.Errorf("get content from original: %w", err)
	}

	contentDoc, err := vocab.UnmarshalToDoc(contentBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal original content to doc: %w", err)
	}

	relatedLinkset, err := anchorLink.Related().Linkset()
	if err != nil {
		return nil, fmt.Errorf("unmarshal 'related' Linkset: %w", err)
	}

	relatedLink := relatedLinkset.Link()
	if relatedLink == nil {
		return nil, fmt.Errorf("'related' Linkset is empty")
	}

	if relatedLink.Anchor() == nil || relatedLink.Anchor().String() != anchorLink.Anchor().String() {
		return nil, fmt.Errorf("anchor of related Linkset [%s] is not equal to the expected anchor [%s]",
			relatedLink.Anchor(), anchorLink.Anchor().String())
	}

	payload, err := gen.CreatePayload(contentDoc, relatedLink.Via(), relatedLink.Up())
	if err != nil {
		return nil, fmt.Errorf("get payload from anchor: %w", err)
	}

	return payload, nil
}

func resolveParents(previousAnchors []*subject.SuffixAnchor) []*url.URL {
	var previous []string

	for _, value := range previousAnchors {
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
			logger.Warn("Invalid parent URI", log.WithURIString(p), log.WithError(err))
		}

		parents[i] = parent
	}

	return parents
}

func contains(values []string, v string) bool {
	for _, val := range values {
		if val == v {
			return true
		}
	}

	return false
}
