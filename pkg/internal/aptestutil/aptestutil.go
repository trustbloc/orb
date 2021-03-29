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

// NewMockService returns a mock 'Service' type actor with the given IRI.
func NewMockService(serviceIRI *url.URL) *vocab.ActorType {
	const (
		keyID      = "https://example1.com/services/orb#main-key"
		keyOwnerID = "https://example1.com/services/orb"
		keyPem     = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
	)

	followers := testutil.NewMockID(serviceIRI, "/followers")
	following := testutil.NewMockID(serviceIRI, "/following")
	inbox := testutil.NewMockID(serviceIRI, "/inbox")
	outbox := testutil.NewMockID(serviceIRI, "/outbox")
	witnesses := testutil.NewMockID(serviceIRI, "/witnesses")
	witnessing := testutil.NewMockID(serviceIRI, "/witnessing")
	liked := testutil.NewMockID(serviceIRI, "/liked")

	publicKey := &vocab.PublicKeyType{
		ID:           keyID,
		Owner:        keyOwnerID,
		PublicKeyPem: keyPem,
	}

	return vocab.NewService(serviceIRI,
		vocab.WithPublicKey(publicKey),
		vocab.WithInbox(inbox),
		vocab.WithOutbox(outbox),
		vocab.WithFollowers(followers),
		vocab.WithFollowing(following),
		vocab.WithWitnesses(witnesses),
		vocab.WithWitnessing(witnessing),
		vocab.WithLiked(liked),
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
