/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aptestutil contains ActivityPub test utilities.
package aptestutil

import (
	"net/url"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

// ServiceOptions are options passed in to NewMockService.
type ServiceOptions struct {
	PublicKey *vocab.PublicKeyType
}

// ServiceOpt is a mock service option.
type ServiceOpt func(options *ServiceOptions)

// WithPublicKey sets the public key on the mock service.
func WithPublicKey(pubKey *vocab.PublicKeyType) ServiceOpt {
	return func(options *ServiceOptions) {
		options.PublicKey = pubKey
	}
}

// NewMockService returns a mock 'Service' type actor with the given IRI and options.
func NewMockService(serviceIRI *url.URL, opts ...ServiceOpt) *vocab.ActorType {
	options := &ServiceOptions{
		PublicKey: NewMockPublicKey(serviceIRI),
	}

	for _, opt := range opts {
		opt(options)
	}

	followers := testutil.NewMockID(serviceIRI, "/followers")
	following := testutil.NewMockID(serviceIRI, "/following")
	inbox := testutil.NewMockID(serviceIRI, "/inbox")
	outbox := testutil.NewMockID(serviceIRI, "/outbox")
	witnesses := testutil.NewMockID(serviceIRI, "/witnesses")
	witnessing := testutil.NewMockID(serviceIRI, "/witnessing")
	liked := testutil.NewMockID(serviceIRI, "/liked")

	return vocab.NewService(serviceIRI,
		vocab.WithPublicKey(options.PublicKey),
		vocab.WithInbox(inbox),
		vocab.WithOutbox(outbox),
		vocab.WithFollowers(followers),
		vocab.WithFollowing(following),
		vocab.WithWitnesses(witnesses),
		vocab.WithWitnessing(witnessing),
		vocab.WithLiked(liked),
	)
}

// NewMockPublicKey returns a mock public key using the given service IRI.
func NewMockPublicKey(serviceIRI *url.URL) *vocab.PublicKeyType {
	const keyPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."

	return vocab.NewPublicKey(
		vocab.WithID(testutil.NewMockID(serviceIRI, "/keys/main-key")),
		vocab.WithOwner(serviceIRI),
		vocab.WithPublicKeyPem(keyPem),
	)
}

// NewMockCollection returns a mock 'Collection' with the given ID and items.
func NewMockCollection(id, first *url.URL, totalItems int) *vocab.CollectionType {
	return vocab.NewCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithTotalItems(totalItems),
		vocab.WithFirst(first),
	)
}

// NewMockOrderedCollection returns a mock 'OrderedCollection' with the given ID and items.
func NewMockOrderedCollection(id, first *url.URL, totalItems int) *vocab.OrderedCollectionType {
	return vocab.NewOrderedCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithTotalItems(totalItems),
		vocab.WithFirst(first),
	)
}

// NewMockCollectionPage returns a mock 'CollectionPage' with the given ID and items.
func NewMockCollectionPage(id, next, collID *url.URL, totalItems int, iris ...*url.URL) *vocab.CollectionPageType {
	var items []*vocab.ObjectProperty

	for _, iri := range iris {
		items = append(items, vocab.NewObjectProperty(vocab.WithIRI(iri)))
	}

	return vocab.NewCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPartOf(collID),
		vocab.WithNext(next),
		vocab.WithTotalItems(totalItems),
	)
}

// NewMockOrderedCollectionPage returns a mock 'OrderedCollectionPage' with the given ID and items.
func NewMockOrderedCollectionPage(id, next, collID *url.URL, totalItems int,
	iris ...*url.URL) *vocab.OrderedCollectionPageType {
	var items []*vocab.ObjectProperty

	for _, iri := range iris {
		items = append(items, vocab.NewObjectProperty(vocab.WithIRI(iri)))
	}

	return vocab.NewOrderedCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPartOf(collID),
		vocab.WithNext(next),
		vocab.WithTotalItems(totalItems),
	)
}
