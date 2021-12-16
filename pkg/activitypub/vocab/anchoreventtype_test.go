/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	sampleGenerator  = "https://sample.com#v0"
	sampleGenerator2 = "https://sample2.com#v0"
)

func TestAnchorEventNil(t *testing.T) {
	var anchorEvent *AnchorEventType

	require.Nil(t, anchorEvent.Index())
	require.Empty(t, anchorEvent.Parent())

	_, err := anchorEvent.AnchorObject(MustParseURL("hl:xxx"))
	require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
}

func TestAnchorEvent(t *testing.T) {
	const (
		relationship1 = "relationship1"
		relationship2 = "relationship2"
	)

	contentObj := &sampleContentObj{Field1: "value1", Field2: "value2"}
	contentObj2 := &sample2ContentObj{Field3: "value3"}

	published := getStaticTime()

	anchorObj, err := NewAnchorObject(sampleGenerator, MustMarshalToDoc(contentObj))
	require.NoError(t, err)
	require.Len(t, anchorObj.URL(), 1)

	anchorObj2, err := NewAnchorObject(sampleGenerator2,
		MustMarshalToDoc(contentObj2),
		WithLink(NewLink(anchorObj.URL()[0], relationship1, relationship2)),
	)
	require.NoError(t, err)
	require.Len(t, anchorObj2.URL(), 1)
	require.Len(t, anchorObj2.Tag(), 1)

	tag := anchorObj2.Tag()[0]
	require.True(t, tag.Type().Is(TypeLink))

	link := tag.Link()
	require.NotNil(t, link)
	require.True(t, link.Rel().Is(relationship1))
	require.True(t, link.Rel().Is(relationship2))
	require.NotNil(t, link.HRef())
	require.Equal(t, anchorObj.URL()[0].String(), link.HRef().String())

	anchorEvent := NewAnchorEvent(
		WithURL(testutil.MustParseURL(
			"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"), //nolint:lll
		),
		WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
		WithIndex(anchorObj.URL()[0]),
		WithPublishedTime(&published),
		WithParent(parentURL1, parentURL2),
		WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj2))),
	)

	bytes, err := canonicalizer.MarshalCanonical(anchorEvent)
	require.NoError(t, err)

	t.Logf("Anchor event: %s", bytes)

	require.Equal(t, testutil.GetCanonical(t, jsonAnchorEvent), string(bytes))

	ae := &AnchorEventType{}
	require.NoError(t, json.Unmarshal(bytes, ae))
	require.Equal(t, anchorEvent.Index().String(), ae.Index().String())

	ao, err := ae.AnchorObject(ae.Index())
	require.NoError(t, err)
	require.NotNil(t, ao)

	_, err = ae.AnchorObject(MustParseURL("hl:xxxxx"))
	require.Error(t, err)
	require.True(t, errors.Is(err, orberrors.ErrContentNotFound))

	contentObjUnmarshalled := &sampleContentObj{}
	MustUnmarshalFromDoc(ao.ContentObject(), contentObjUnmarshalled)

	require.Equal(t, contentObj.Field1, contentObjUnmarshalled.Field1)
	require.Equal(t, contentObj.Field2, contentObjUnmarshalled.Field2)

	require.NoError(t, ae.Validate())
}

func TestAnchorObjectNil(t *testing.T) {
	var anchorObj *AnchorObjectType

	require.Nil(t, anchorObj.ContentObject())
}

func TestAnchorEventType_Validate(t *testing.T) {
	anchors := testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")

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
			WithIndex(anchors),
		)

		e := ae.Validate()
		require.Error(t, e)
		require.Contains(t, e.Error(), "unable to find the attachment that matches the anchors URL in the anchor event")
	})

	t.Run("Unsupported attachment", func(t *testing.T) {
		ae := NewAnchorEvent(
			WithIndex(anchors),
			WithAttachment(NewObjectProperty(WithObject(
				NewObject(
					WithType(TypeVerifiableCredential),
				),
			))),
		)

		e := ae.Validate()
		require.Error(t, e)
		require.Contains(t, e.Error(), "unsupported attachment type")
	})

	t.Run("Missing anchor object URL", func(t *testing.T) {
		anchorObj := &AnchorObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorObjNoURL), anchorObj))

		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithIndex(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor object must have exactly one URL")
	})

	t.Run("Anchor URL mismatch", func(t *testing.T) {
		anchorObj, err := NewAnchorObject(sampleGenerator,
			MustMarshalToDoc(&sampleContentObj{Field1: "value1", Field2: "value2"}),
		)
		require.NoError(t, err)
		require.Len(t, anchorObj.URL(), 1)

		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithIndex(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		err = ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find the attachment that matches the anchors URL in the anchor event")
	})

	t.Run("No content object", func(t *testing.T) {
		anchorObj := &AnchorObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorObjNoContentObj), anchorObj))

		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithIndex(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "content object is required in anchor event")
	})

	t.Run("No generator", func(t *testing.T) {
		anchorObj := &AnchorObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorObjNoGenerator), anchorObj))

		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithIndex(anchors),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "generator is required in anchor event")
	})

	t.Run("Invalid content object hash", func(t *testing.T) {
		anchorObj := &AnchorObjectType{}
		require.NoError(t, json.Unmarshal([]byte(jsonAnchorObjInvalidURL), anchorObj))

		ae := NewAnchorEvent(
			WithURL(testutil.MustParseURL(
				"hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk", //nolint:lll
			)),
			WithAttributedTo(testutil.MustParseURL("https://orb.domain1.com/services/orb")),
			WithIndex(anchorObj.URL()[0]),
			WithPublishedTime(&published),
			WithParent(parentURL1, parentURL2),
			WithAttachment(NewObjectProperty(WithAnchorObject(anchorObj))),
		)

		err := ae.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not match the anchor object URL")
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

type sampleContentObj struct {
	Field1 string `json:"field_1"`
	Field2 string `json:"field_2"`
}

type sample2ContentObj struct {
	Field3 string `json:"field_3"`
}

const (
	//nolint:lll
	jsonAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "index": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
  "attachment": [
    {
      "contentObject": {
        "field_1": "value1",
        "field_2": "value2"
      },
      "generator": "https://sample.com#v0",
      "type": "AnchorObject",
      "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA"
    },
    {
      "contentObject": {
        "field_3": "value3"
      },
      "generator": "https://sample2.com#v0",
      "tag": [
        {
          "href": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
          "rel": [
            "relationship1",
            "relationship2"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiDyIrycKpCTdNYXESE4V_2HobZnBl7-fJVxJjYr2awQ_Q"
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
	jsonAnchorObjInvalidURL = `{
      "contentObject": {
        "field_1": "value1",
        "field_2": "value2"
      },
      "generator": "https://sample.com#v0",
      "type": "AnchorObject",
      "url": "hl:uEiAcDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
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
    }`

	jsonAnchorObjNoURL = `{
      "contentObject": {
        "field_1": "value1",
        "field_2": "value2"
      },
      "generator": "https://sample.com#v0",
      "type": "AnchorObject"
}`
	jsonAnchorObjNoContentObj = `{
      "generator": "https://sample.com#v0",
      "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
      "type": "AnchorObject"
}`
	jsonAnchorObjNoGenerator = `{
      "url": "hl:uEiAfDoaIG1rgG9-HRnRMveKAhR-5kjwZXOAQ1ABl1qBCWA",
      "type": "AnchorObject"
}`
)
