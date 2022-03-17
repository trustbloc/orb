/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package samplegenerator

import (
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator/didorbgenerator"
)

const (
	// ID specifies the ID of the generator.
	ID = "https://w3id.org/test#v1"

	// Namespace specifies the namespace of the generator.
	Namespace = "did:test"

	// Version specifies the version of the generator.
	Version = uint64(1)
)

// Generator implements a generator used by tests. It also demonstrates how to extend an existing generator
// implementation in order to support future versions.
type Generator struct {
	*didorbgenerator.Generator
}

// New returns a new test generator.
func New() *Generator {
	return &Generator{
		Generator: didorbgenerator.New(
			didorbgenerator.WithID(vocab.MustParseURL(ID)),
			didorbgenerator.WithNamespace(Namespace),
			didorbgenerator.WithVersion(Version),
		),
	}
}
