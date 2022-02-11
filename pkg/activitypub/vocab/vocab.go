/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

// Context defines the object context.
type Context string

const (
	// ContextActivityStreams is the ActivityStreams context.
	ContextActivityStreams Context = "https://www.w3.org/ns/activitystreams"
	// ContextSecurity is the security context.
	ContextSecurity Context = "https://w3id.org/security/v1"
	// ContextCredentials is the verifiable credential context.
	ContextCredentials Context = "https://www.w3.org/2018/credentials/v1"
	// ContextActivityAnchors is the Activity Anchors context.
	ContextActivityAnchors Context = "https://w3id.org/activityanchors/v1"
)

//nolint:gochecknoglobals
var (
	// PublicIRI indicates that the object is public, i.e. it may be viewed by anyone.
	PublicIRI = MustParseURL("https://www.w3.org/ns/activitystreams#Public")

	// AnchorWitnessTargetIRI indicates that the object/target of the activity is an anchor witness.
	AnchorWitnessTargetIRI = MustParseURL("https://w3id.org/activityanchors#AnchorWitness")
)

// Type indicates the type of the object.
type Type string

const (
	// TypeCollection specifies the 'Collection' object type.
	TypeCollection Type = "Collection"
	// TypeOrderedCollection specifies the 'OrderedCollection' object type.
	TypeOrderedCollection Type = "OrderedCollection"
	// TypeCollectionPage specifies the 'CollectionPage' object type.
	TypeCollectionPage Type = "CollectionPage"
	// TypeOrderedCollectionPage specifies the 'OrderedCollectionPage' object type.
	TypeOrderedCollectionPage Type = "OrderedCollectionPage"

	// TypeService specifies the 'Service' actor type.
	TypeService Type = "Service"
	// TypeCreate specifies the 'Create' activity type.
	TypeCreate Type = "Create"
	// TypeAnnounce specifies the 'Announce' activity type.
	TypeAnnounce Type = "Announce"
	// TypeFollow specifies the 'Follow' activity type.
	TypeFollow Type = "Follow"
	// TypeAccept specifies the 'Accept' activity type.
	TypeAccept Type = "Accept"
	// TypeReject specifies the 'Reject' activity type.
	TypeReject Type = "Reject"
	// TypeLike specifies the 'Like' activity type.
	TypeLike Type = "Like"
	// TypeInvite specifies the 'Invite' activity type.
	TypeInvite Type = "Invite"

	// TypeLink specifies the 'Link' object type.
	TypeLink Type = "Link"

	// TypeVerifiableCredential specifies the "VerifiableCredential" object type.
	TypeVerifiableCredential Type = "VerifiableCredential"

	// TypeContentAddressedStorage specifies the "ContentAddressedStorage" object type.
	TypeContentAddressedStorage Type = "ContentAddressedStorage"
	// TypeAnchorEvent specifies the "AnchorEvent" object type.
	TypeAnchorEvent Type = "AnchorEvent"
	// TypeAnchorObject specifies the "AnchorObject" object type.
	TypeAnchorObject Type = "AnchorObject"
	// TypeAnchorReceipt specifies the "AnchorReceipt" object type.
	TypeAnchorReceipt Type = "AnchorReceipt"
	// TypeOffer specifies the "Offer" activity type.
	TypeOffer Type = "Offer"
	// TypeUndo specifies the "Undo" activity type.
	TypeUndo Type = "Undo"
)

const (
	// RelationshipWitness defines the 'witness' relationship of a Link.
	RelationshipWitness = "witness"
)

const (
	propertyContext      = "@context"
	propertyID           = "id"
	propertyType         = "type"
	propertyTo           = "to"
	propertyPublished    = "published"
	propertyActor        = "actor"
	propertyCurrent      = "current"
	propertyFirst        = "first"
	propertyLast         = "last"
	propertyItems        = "items"
	propertyObject       = "object"
	propertyResult       = "result"
	propertyTarget       = "target"
	propertyEndTime      = "endTime"
	propertyStartTime    = "startTime"
	propertyTotalItems   = "totalItems"
	propertyURL          = "url"
	propertyAttributedTo = "attributedTo"
	propertyInReplyTo    = "inReplyTo"
	propertyAttachment   = "attachment"
	propertyIndex        = "index"
	propertyParent       = "parent"
)

// MediaType defines a type of encoding for content embedded within a document.
type MediaType = string

const (
	// JSONMediaType indicates that the content is plain JSON string.
	JSONMediaType MediaType = "application/json"
	// GzipMediaType indicates that the content is compressed with gzip and base64-encoded.
	GzipMediaType MediaType = "application/gzip"
)

func reservedProperties() []string {
	return []string{
		propertyContext,
		propertyID,
		propertyType,
		propertyTo,
		propertyPublished,
		propertyActor,
		propertyCurrent,
		propertyFirst,
		propertyLast,
		propertyItems,
		propertyObject,
		propertyResult,
		propertyTarget,
		propertyEndTime,
		propertyStartTime,
		propertyTotalItems,
		propertyURL,
		propertyAttributedTo,
		propertyInReplyTo,
		propertyAttachment,
		propertyParent,
		propertyIndex,
	}
}

// Document defines a JSON document as a map.
type Document map[string]interface{}

// MergeWith merges the document with the given document. Any duplicate fields
// in the given document are ignored.
func (doc Document) MergeWith(other Document) {
	for k, v := range other {
		if _, ok := doc[k]; !ok {
			doc[k] = v
		}
	}
}

// Unmarshal unmarshals the document to the given object.
func (doc Document) Unmarshal(obj interface{}) error {
	return UnmarshalFromDoc(doc, obj)
}
