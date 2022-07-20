/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbtestgenerator

import (
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator/didorbgenerator"
	"github.com/trustbloc/orb/pkg/anchor/subject"
)

const (
	// ID specifies the ID of the generator.
	ID = "https://w3id.org/orb#v777"

	// Namespace specifies the namespace of the generator.
	Namespace = "did:orb"

	testProtocolGenesisTime = 777

	// Version specifies the version of the generator - corresponds to protocol genesis time.
	Version = uint64(testProtocolGenesisTime)
)

// Generator generates a content object for did:orb anchor events.
type Generator struct {
	orbGenerator *didorbgenerator.Generator
}

// New returns a new generator.
func New() *Generator {
	gen := didorbgenerator.New(didorbgenerator.WithNamespace(Namespace),
		didorbgenerator.WithID(vocab.MustParseURL(ID)), didorbgenerator.WithVersion(Version))

	return &Generator{orbGenerator: gen}
}

// ID returns the ID of the generator.
func (g *Generator) ID() *url.URL {
	return g.orbGenerator.ID()
}

// Namespace returns the Namespace for the DID method.
func (g *Generator) Namespace() string {
	return g.orbGenerator.Namespace()
}

// Version returns the Version of this generator.
func (g *Generator) Version() uint64 {
	return g.orbGenerator.Version()
}

// CreateContentObject creates a content object from the given payload.
func (g *Generator) CreateContentObject(payload *subject.Payload) (vocab.Document, error) {
	return g.orbGenerator.CreateContentObject(payload)
}

// CreatePayload creates a payload from the given anchor event.
func (g *Generator) CreatePayload(doc vocab.Document, coreIndexURI *url.URL,
	anchors []*url.URL) (*subject.Payload, error) {
	return g.orbGenerator.CreatePayload(doc, coreIndexURI, anchors)
}

// ValidateAnchorCredential validates the anchor credential against the given content.
func (g *Generator) ValidateAnchorCredential(vc *verifiable.Credential, originalContentBytes []byte) error {
	return g.orbGenerator.ValidateAnchorCredential(vc, originalContentBytes)
}
