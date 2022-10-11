/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package aptestutil contains ActivityPub test utilities.
package aptestutil

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
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
func NewMockCollection(id, first, last *url.URL, totalItems int) *vocab.CollectionType {
	return vocab.NewCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithTotalItems(totalItems),
		vocab.WithFirst(first),
		vocab.WithLast(last),
	)
}

// NewMockOrderedCollection returns a mock 'OrderedCollection' with the given ID and items.
func NewMockOrderedCollection(id, first, last *url.URL, totalItems int) *vocab.OrderedCollectionType {
	return vocab.NewOrderedCollection(nil,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithTotalItems(totalItems),
		vocab.WithFirst(first),
		vocab.WithLast(last),
	)
}

// NewMockCollectionPage returns a mock 'CollectionPage' with the given ID and items.
func NewMockCollectionPage(id, next, prev, collID *url.URL, totalItems int,
	items ...*vocab.ObjectProperty) *vocab.CollectionPageType {
	return vocab.NewCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPartOf(collID),
		vocab.WithNext(next),
		vocab.WithPrev(prev),
		vocab.WithTotalItems(totalItems),
	)
}

// NewMockOrderedCollectionPage returns a mock 'OrderedCollectionPage' with the given ID and items.
func NewMockOrderedCollectionPage(id, next, prev, collID *url.URL, totalItems int,
	items ...*vocab.ObjectProperty) *vocab.OrderedCollectionPageType {
	return vocab.NewOrderedCollectionPage(items,
		vocab.WithContext(vocab.ContextActivityStreams),
		vocab.WithID(id),
		vocab.WithPartOf(collID),
		vocab.WithNext(next),
		vocab.WithPrev(prev),
		vocab.WithTotalItems(totalItems),
	)
}

// NewMockCreateActivities returns the given number of mock 'Create' activities.
func NewMockCreateActivities(num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		activities[i] = NewMockCreateActivity(
			testutil.MustParseURL(fmt.Sprintf("https://create_%d", i)),
			testutil.MustParseURL(fmt.Sprintf("https://obj_%d", i)),
			vocab.NewObjectProperty(vocab.WithAnchorEvent(vocab.NewAnchorEvent(nil))),
		)
	}

	return activities
}

// NewMockAnnounceActivities returns the given number of mock 'Announce' activities.
func NewMockAnnounceActivities(num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		activities[i] = NewMockAnnounceActivity(
			testutil.MustParseURL(fmt.Sprintf("https://create_%d", i)),
			testutil.MustParseURL(fmt.Sprintf("https://obj_%d", i)),
			vocab.NewObjectProperty(vocab.WithAnchorEvent(vocab.NewAnchorEvent(nil))),
		)
	}

	return activities
}

// NewMockCreateActivity returns a new mock Create activity.
func NewMockCreateActivity(actorIRI, toIRI *url.URL, obj *vocab.ObjectProperty) *vocab.ActivityType {
	published := time.Now()

	return vocab.NewCreateActivity(
		obj,
		vocab.WithID(NewActivityID(actorIRI)),
		vocab.WithActor(actorIRI),
		vocab.WithTo(toIRI),
		vocab.WithPublishedTime(&published),
	)
}

// NewMockAnnounceActivity returns a new mock Announce activity.
func NewMockAnnounceActivity(actorIRI, toIRI *url.URL, obj *vocab.ObjectProperty) *vocab.ActivityType {
	published := time.Now()

	return vocab.NewAnnounceActivity(
		obj,
		vocab.WithID(NewActivityID(actorIRI)),
		vocab.WithActor(actorIRI),
		vocab.WithTo(toIRI),
		vocab.WithPublishedTime(&published),
	)
}

// NewMockLikeActivities returns the given number of mock 'Like' activities.
func NewMockLikeActivities(num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		activities[i] = NewMockLikeActivity(fmt.Sprintf("https://like_%d", i), fmt.Sprintf("https://obj_%d", i))
	}

	return activities
}

// NewMockLikeActivity returns a mock 'Like' activity.
func NewMockLikeActivity(id, objID string) *vocab.ActivityType {
	return vocab.NewLikeActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorEvent(
				vocab.NewAnchorEvent(
					nil,
					vocab.WithURL(testutil.MustParseURL(objID)),
				),
			),
		),
		vocab.WithID(testutil.MustParseURL(id)),
	)
}

// NewMockAnchorLink returns a new mock anchor Link.
func NewMockAnchorLink(t *testing.T) *linkset.Link {
	t.Helper()

	profile := testutil.MustParseURL("https://w3id.org/orb#v0")

	parentURL1 := testutil.MustParseURL("hl:uEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzNRNFNGM2JQLXFiMGk5TUl6X2tfbi1yS2ktQmhTZ2NPazhxb0tWY0pxcmd4QmlwZnM6Ly9iYWZrcmVpZnhpb2NpbHhudDcydTMyaXh1eWl6NzR0N2g3a3prZjZheWtrYTRoamhzdmlmZmxxdGt2eQ") //nolint:lll

	sidetreeIndexHL := NewRandomHashlink(t)

	itemHRef1 := testutil.MustParseURL("did:orb:uEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg:EiBASbC8BstzmFwGyFVPY4ToGh_75G74WHKpqNNXwQ7RaA") //nolint:lll
	prevHRef1 := testutil.MustParseURL("hl:uEiC3Q4SF3bP-qb0i9MIz_k_n-rKi-BhSgcOk8qoKVcJqrg")

	itemHRef2 := testutil.MustParseURL("did:orb:uEiCWKM6q1fGqlpW4HjpXYP5KbM8bLRQv_wZkDwyV_rp_JQ:EiB9lWJFoXkUFyak38-hhjp8DK3ceNVtkhdTm_PvoR8JdA") //nolint:lll

	author := testutil.MustParseURL("https://orb.domain2.com/services/orb")

	originalLinkset := linkset.New(
		linkset.NewAnchorLink(sidetreeIndexHL, author, profile,
			[]*linkset.Item{
				linkset.NewItem(itemHRef1, prevHRef1),
				linkset.NewItem(itemHRef2, nil),
			},
		),
	)

	originalLSBytes := testutil.MarshalCanonical(t, originalLinkset)
	anchor, originalRef, err := linkset.NewAnchorRef(originalLSBytes, datauri.MediaTypeDataURIGzipBase64,
		linkset.TypeLinkset)
	require.NoError(t, err)

	relatedLinkset := linkset.New(
		linkset.NewRelatedLink(anchor, profile,
			testutil.MustParseURL(fmt.Sprintf("%s:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRHdWeXFhdTFjVl9XUzhhVFFLTDZkUEZxNkd2Rm82cW4tTVFURkc5VVhKbVF4QmlwZnM6Ly9iYWZrcmVpaHFrNHZqdm8yeGN4NndqcGRqZ3FmYzdqMnBjMnhpbnBjMmhrdmg3ZGNiZ2ZkcGtyb2p0ZQ", //nolint:lll
				sidetreeIndexHL.String())),
			parentURL1,
		),
	)

	relatedLSBytes := testutil.MarshalCanonical(t, relatedLinkset)

	upDataURI, err := datauri.New(relatedLSBytes, datauri.MediaTypeDataURIGzipBase64)
	require.NoError(t, err)

	related := linkset.NewReference(upDataURI, linkset.TypeLinkset)

	reply1DataURI, err := datauri.New([]byte(testutil.GetCanonical(t, verifiableCred)), datauri.MediaTypeDataURIGzipBase64)
	require.NoError(t, err)

	return linkset.NewLink(anchor, author, profile, originalRef, related,
		linkset.NewReference(reply1DataURI, linkset.TypeJSONLD),
	)
}

// NewMockAnchorEvent returns a new mock AnchorEvent.
func NewMockAnchorEvent(t *testing.T, anchorLink *linkset.Link) *vocab.AnchorEventType {
	t.Helper()

	anchorLinksetDoc, err := vocab.MarshalToDoc(linkset.New(anchorLink))
	require.NoError(t, err)

	anchorURI, err := hashlink.New().CreateHashLink(testutil.MarshalCanonical(t, anchorLinksetDoc), nil)
	require.NoError(t, err)

	return vocab.NewAnchorEvent(
		vocab.NewObjectProperty(vocab.WithDocument(anchorLinksetDoc)),
		vocab.WithURL(testutil.MustParseURL(anchorURI)),
	)
}

// NewMockAnchorEventRef returns a new mock AnchorEvent reference.
func NewMockAnchorEventRef(t *testing.T) *vocab.AnchorEventType {
	t.Helper()

	return vocab.NewAnchorEvent(
		nil,
		vocab.WithURL(NewRandomHashlink(t)),
	)
}

// NewRandomHashlink returns a randomly generated hashlink.
func NewRandomHashlink(t *testing.T) *url.URL {
	t.Helper()

	tm := time.Now()

	randomBytes, err := json.Marshal(tm)
	require.NoError(t, err)

	hl, err := hashlink.New().CreateHashLink(randomBytes, nil)
	require.NoError(t, err)

	return testutil.MustParseURL(hl)
}

// NewActivityID returns a generated activity ID.
func NewActivityID(id fmt.Stringer) *url.URL {
	return testutil.NewMockID(id, uuid.New().String())
}

//nolint: gosec,goimports
const verifiableCred = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "credentialSubject": "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
  "id": "https://orb.domain1.com/vc/d53b1df9-1acf-4389-a006-0f88496afe46",
  "issuanceDate": "2022-03-15T21:21:54.62437567Z",
  "issuer": "https://orb.domain1.com",
  "proof": [
    {
      "created": "2022-03-15T21:21:54.631Z",
      "domain": "http://orb.vct:8077/maple2020",
      "proofPurpose": "assertionMethod",
      "proofValue": "gRPF8XAA4iYMwl26RmFGUoN99wuUnD_igmvIlzzDpPRLVDtmA8wrNbUdJIAKKhyMJFju8OjciSGYMY_bDRjBAw",
      "type": "Ed25519Signature2020",
      "verificationMethod": "did:web:orb.domain1.com#orb1key2"
    },
    {
      "created": "2022-03-15T21:21:54.744899145Z",
      "domain": "https://orb.domain2.com",
      "proofPurpose": "assertionMethod",
      "proofValue": "FX58osRrwU11IrUfhVTi0ucrNEq05Cv94CQNvd8SdoY66fAjwU2--m8plvxwVnXmxnlV23i6htkq4qI8qrDgAA",
      "type": "Ed25519Signature2020",
      "verificationMethod": "did:web:orb.domain2.com#orb2key"
    }
  ],
  "type": "VerifiableCredential"
}`
