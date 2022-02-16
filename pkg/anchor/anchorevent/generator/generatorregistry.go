/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package generator

import (
	"fmt"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator/didorbgenerator"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator/didorbtestgenerator"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/generator/samplegenerator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

// Generator defines the operations of a content object generator.
type Generator interface {
	ID() string
	Namespace() string
	Version() uint64
	CreateContentObject(payload *subject.Payload) (vocab.Document, error)
	CreatePayload(anchorEvent *vocab.AnchorEventType) (*subject.Payload, error)
}

// Registry maintains a registry of content object generators.
type Registry struct {
	generators []Generator
}

// NewRegistry returns a new generator registry.
func NewRegistry() *Registry {
	return &Registry{
		generators: []Generator{
			didorbgenerator.New(),
			samplegenerator.New(),
			didorbtestgenerator.New(),
		},
	}
}

// Get returns the generator for the given ID.
func (r *Registry) Get(id string) (Generator, error) {
	for _, generator := range r.generators {
		if generator.ID() == id {
			return generator, nil
		}
	}

	return nil, fmt.Errorf("generator not found [%s]: %w", id, orberrors.ErrContentNotFound)
}

// GetByNamespaceAndVersion returns the generator for the given namespace and version.
func (r *Registry) GetByNamespaceAndVersion(ns string, ver uint64) (Generator, error) {
	for _, generator := range r.generators {
		if generator.Namespace() == ns && generator.Version() == ver {
			return generator, nil
		}
	}

	return nil, fmt.Errorf("generator not found for namespace [%s] and version [%d]: %w",
		ns, ver, orberrors.ErrContentNotFound)
}
