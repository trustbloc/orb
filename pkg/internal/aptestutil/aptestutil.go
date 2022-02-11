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
	"github.com/trustbloc/orb/pkg/hashlink"
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
			vocab.NewObjectProperty(vocab.WithAnchorEvent(vocab.NewAnchorEvent())),
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
			vocab.NewObjectProperty(vocab.WithAnchorEvent(vocab.NewAnchorEvent())),
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
					vocab.WithURL(testutil.MustParseURL(objID)),
					vocab.WithURL(testutil.MustParseURL("https://example.com/cas/bafkd34G7hD6gbj94fnKm5D")),
				),
			),
		),
		vocab.WithID(testutil.MustParseURL(id)),
	)
}

// NewMockAnchorEvent returns a new mock AnchorEvent.
func NewMockAnchorEvent(t *testing.T) *vocab.AnchorEventType {
	t.Helper()

	const generator = "https://w3id.org/orb#v0"

	var (
		parentURL1 = testutil.MustParseURL("hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5") //nolint:lll
		parentURL2 = testutil.MustParseURL("hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp") //nolint:lll
	)

	witnessAnchorObj, err := vocab.NewAnchorObject(
		generator,
		vocab.MustUnmarshalToDoc([]byte(verifiableCred)),
		vocab.GzipMediaType,
	)
	require.NoError(t, err)
	require.Len(t, witnessAnchorObj.URL(), 1)

	published := time.Now()

	indexAnchorObj, err := vocab.NewAnchorObject(
		generator,
		vocab.MustMarshalToDoc(
			&sampleContentObj{
				Field1: "value1",
				Field2: "value2",
			},
		),
		vocab.GzipMediaType,
		vocab.WithLink(vocab.NewLink(witnessAnchorObj.URL()[0], vocab.RelationshipWitness)),
	)
	require.NoError(t, err)
	require.Len(t, indexAnchorObj.URL(), 1)

	anchorEvent := vocab.NewAnchorEvent(
		vocab.WithURL(NewRandomHashlink(t)),
		vocab.WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
		vocab.WithIndex(indexAnchorObj.URL()[0]),
		vocab.WithPublishedTime(&published),
		vocab.WithParent(parentURL1, parentURL2),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(witnessAnchorObj))),
	)

	return anchorEvent
}

// NewMockAnchorEventRef returns a new mock AnchorEvent reference.
func NewMockAnchorEventRef(t *testing.T) *vocab.AnchorEventType {
	t.Helper()

	return vocab.NewAnchorEvent(
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

type sampleContentObj struct {
	Field1 string `json:"field_1"`
	Field2 string `json:"field_2"`
}

const verifiableCred = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "type": "VerifiableCredential",
  "issuer": "https://sally.example.com/services/anchor",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
    "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
  },
  "proof": [
    {
      "type": "JsonWebSignature2020",
      "proofPurpose": "assertionMethod",
      "created": "2021-01-27T09:30:00Z",
      "verificationMethod": "did:example:abcd#key",
      "domain": "sally.example.com",
      "jws": "eyJ..."
    },
    {
      "type": "JsonWebSignature2020",
      "proofPurpose": "assertionMethod",
      "created": "2021-01-27T09:30:05Z",
      "verificationMethod": "did:example:abcd#key",
      "domain": "https://witness1.example.com/ledgers/maple2021",
      "jws": "eyJ..."
    }
  ]
}`
