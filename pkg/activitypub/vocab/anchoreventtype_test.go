/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestAnchorEventNil(t *testing.T) {
	var anchorEvent *AnchorEventType

	require.Nil(t, anchorEvent.Anchors())
	require.Empty(t, anchorEvent.Parent())
	require.Nil(t, anchorEvent.Witness())
	require.Nil(t, anchorEvent.ContentObject())
}

func TestAnchorEvent(t *testing.T) {
	const (
		generator  = "https://w3id.org/orb#v0"
		resourceID = "did:orb:uAAA:EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
	)

	var (
		anchors = testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")
		subject = testutil.MustParseURL("hl:uEiB1miJeUsG7PiLvFel8DKoluzDVl3OnpjKgAGZS588PXQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWR2dGlyZjR1d2J4bTdjZjN5djVmNmF6a3JmeG15bmxmM3R1NnRkZmlhYW16am9wdHlwbHU") //nolint:lll
	)

	witness, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(verifiableCred)))
	require.NoError(t, err)

	published := getStaticTime()

	anchorEvent := NewAnchorEvent(
		WithURL(testutil.MustParseURL(
			"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"), //nolint:lll
		),
		WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
		WithAnchors(anchors),
		WithPublishedTime(&published),
		WithParent(parentURL1, parentURL2),
		WithAttachment(NewObjectProperty(WithAnchorObject(
			NewAnchorObject(
				NewContentObject(generator,
					subject,
					NewResource(resourceID, ""),
				),
				witness,
				WithURL(anchors),
			),
		))),
	)

	bytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	require.NoError(t, err)

	t.Logf("Anchor event: %s", bytes)

	require.Equal(t, testutil.GetCanonical(t, jsonAnchorEvent), string(bytes))

	ae := &AnchorEventType{}
	require.NoError(t, json.Unmarshal(bytes, ae))
	require.Equal(t, anchors.String(), ae.Anchors().String())

	contentObj := ae.ContentObject()
	require.NotNil(t, contentObj)

	require.Equal(t, generator, contentObj.Generator())
	require.Equal(t, subject.String(), contentObj.Subject.URL().String())
	require.Len(t, contentObj.Resources(), 1)
	require.Equal(t, resourceID, contentObj.Resources()[0].ID)
	require.Empty(t, contentObj.Resources()[0].PreviousAnchor)
	require.Equal(t, witness, anchorEvent.Witness())

	require.NoError(t, ae.Validate())
}

func TestAnchorObjectNil(t *testing.T) {
	var anchorObj *AnchorObjectType

	require.Nil(t, anchorObj.ContentObject())
	require.Empty(t, anchorObj.Witness())
}

func TestContentObjectNil(t *testing.T) {
	var contentObj *ContentObjectType

	require.Equal(t, "", contentObj.Generator())
	require.Empty(t, contentObj.Resources())
}

func TestAnchorEventType_Validate(t *testing.T) {
	const (
		generator  = "https://w3id.org/orb#v0"
		resourceID = "did:orb:uAAA:EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
	)

	var (
		anchors = testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")
		subject = testutil.MustParseURL(
			"hl:uEiB1miJeUsG7PiLvFel8DKoluzDVl3OnpjKgAGZS588PXQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWR2dGlyZjR1d2J4bTdjZjN5djVmNmF6a3JmeG15bmxmM3R1NnRkZmlhYW16am9wdHlwbHU", //nolint:lll
		)
	)

	witness, err := NewObjectWithDocument(MustUnmarshalToDoc([]byte(verifiableCred)))
	require.NoError(t, err)

	published := time.Now()

	t.Run("Nil anchor event", func(t *testing.T) {
		var ae *AnchorEventType

		require.Error(t, ae.Validate(), "nil anchor event")
	})

	t.Run("No anchors URL", func(t *testing.T) {
		ae := NewAnchorEvent()

		require.Error(t, ae.Validate(), "anchors URL is required on anchor event")
	})

	t.Run("No attachment", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithAnchors(anchors),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor event must have exactly one attachment")
	})

	t.Run("Unsupported attachment", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithAnchors(anchors),
			WithAttachment(NewObjectProperty(WithObject(
				NewObject(
					WithType(TypeVerifiableCredential),
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported attachment type")
	})

	t.Run("Missing anchor object URL", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithAnchors(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(
				NewAnchorObject(
					NewContentObject(generator,
						subject,
						NewResource(resourceID, ""),
					),
					witness,
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor object must have exactly one URL")
	})

	t.Run("Anchor URL mismatch", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithAnchors(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(
				NewAnchorObject(
					NewContentObject(generator,
						subject,
						NewResource(resourceID, ""),
					),
					witness,
					WithURL(subject),
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be the same as the anchors URL in the anchor event URL")
	})

	t.Run("No content object", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithAnchors(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(
				NewAnchorObject(
					nil,
					witness,
					WithURL(anchors),
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "content object is required in anchor event")
	})

	t.Run("Invalid content object hash", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithAnchors(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(
				NewAnchorObject(
					NewContentObject("https://w3id.org/orb#v1",
						subject,
						NewResource(resourceID, ""),
					),
					witness,
					WithURL(anchors),
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match the anchor object URL")
	})

	t.Run("No witness", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithAnchors(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(
				NewAnchorObject(
					NewContentObject(generator,
						subject,
						NewResource(resourceID, ""),
					),
					nil,
					WithURL(anchors),
				),
			))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness is required in anchor event")
	})
}

func TestAnchorEventType_JustURL(t *testing.T) {
	anchorEvent := NewAnchorEvent(
		WithURL(testutil.MustParseURL(
			"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
		)),
	)

	bytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	require.NoError(t, err)

	t.Logf("Anchor event: %s", bytes)

	require.Equal(t, testutil.GetCanonical(t, jsonAnchorEventRef), string(bytes))

	require.NoError(t, anchorEvent.Validate())
}

const (
	//nolint:lll
	jsonAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uAAA:EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
            }
          ]
        },
        "subject": "hl:uEiB1miJeUsG7PiLvFel8DKoluzDVl3OnpjKgAGZS588PXQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWR2dGlyZjR1d2J4bTdjZjN5djVmNmF6a3JmeG15bmxmM3R1NnRkZmlhYW16am9wdHlwbHU"
      },
      "type": "AnchorObject",
      "url": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
      "witness": {
        "@context": "https://www.w3.org/2018/credentials/v1",
        "credentialSubject": {
          "id": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
        },
        "issuanceDate": "2021-01-27T09:30:10Z",
        "issuer": "https://sally.example.com/services/anchor",
        "proof": [
          {
            "created": "2021-01-27T09:30:00Z",
            "domain": "sally.example.com",
            "jws": "eyJ...",
            "proofPurpose": "assertionMethod",
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:example:abcd#key"
          },
          {
            "created": "2021-01-27T09:30:05Z",
            "domain": "https://witness1.example.com/ledgers/maple2021",
            "jws": "eyJ...",
            "proofPurpose": "assertionMethod",
            "type": "JsonWebSignature2020",
            "verificationMethod": "did:example:abcd#key"
          }
        ],
        "type": "VerifiableCredential"
      }
    }
  ],
  "attributedTo": "https://orb.domain1.com/services/orb",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "published": "2021-01-27T09:30:10Z",
  "type": "AnchorEvent",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`

	//nolint:lll
	jsonAnchorEventRef = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "type": "AnchorEvent",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`
)
