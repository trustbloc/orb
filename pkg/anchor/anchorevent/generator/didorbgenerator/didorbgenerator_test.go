/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didorbgenerator

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	coreIndexHL1 = "hl:uEiBaZqszLIDqXbfh3WSVIEye9_vYCOl4KKMQ5Q9JU3NaoQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQmFacXN6TElEcVhiZmgzV1NWSUV5ZTlfdllDT2w0S0tNUTVROUpVM05hb1E" //nolint:lll
	coreIndexHL2 = "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg:uoQ-BeEJpcGZzOi8vYmFma3JlaWU1bWJyeHlpZGUzenBhd2RtcGc3NmV5NDUyamE3dmVhd3hod2ZucXdhdHQ1cmt1YjdlbGk"             //nolint:lll
	suffix1      = "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
	suffix2      = "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw"
	parentHL1    = "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE" //nolint:lll
	parentMH1    = "uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
	service1     = "https://domain1.com/services/orb"
)

func TestNew(t *testing.T) {
	t.Run("Default ID, Namespace, Version", func(t *testing.T) {
		gen := New()
		require.NotNil(t, gen)

		require.Equal(t, ID, gen.ID())
		require.Equal(t, Namespace, gen.Namespace())
		require.Equal(t, Version, gen.Version())
	})

	t.Run("Alternate ID, Namespace, Version", func(t *testing.T) {
		const (
			id        = "https://some_other_generator#v1"
			namespace = "did:other"
			version   = uint64(1)
		)

		gen := New(WithID(id), WithNamespace(namespace), WithVersion(version))
		require.NotNil(t, gen)

		require.Equal(t, id, gen.ID())
		require.Equal(t, namespace, gen.Namespace())
		require.Equal(t, version, gen.Version())
	})
}

func TestGenerator_CreateContentObject(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	t.Run("Success", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL2,
			PreviousAnchors: []*subject.SuffixAnchor{
				{
					Suffix: suffix1,
				},
				{
					Suffix: suffix2,
					Anchor: "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQXVCUUtQWVhsOTBpM2hvMGFKc0VHSnBYQ3J2WnZiUkJ0WEg2UlVGMHJaTEE", //nolint:lll
				},
			},
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.NoError(t, err)
		require.NotNil(t, contentObj)

		contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
		require.NoError(t, err)

		t.Logf("ContentObject: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonContentObj), string(contentObjBytes))
	})

	t.Run("No core index", func(t *testing.T) {
		payload := &subject.Payload{}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing core index")
		require.Nil(t, contentObj)
	})

	t.Run("No previous anchors", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL1,
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing previous anchors")
		require.Nil(t, contentObj)
	})

	t.Run("Invalid hashlink in previous anchor", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex: coreIndexHL1,
			PreviousAnchors: []*subject.SuffixAnchor{
				{
					Suffix: suffix2,
					Anchor: "uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA",
				},
			},
		}

		contentObj, err := gen.CreateContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of parts for previous anchor hashlink")
		require.Nil(t, contentObj)
	})
}

func TestGenerator_GetPayloadFromAnchorEvent(t *testing.T) {
	gen := New()
	require.NotNil(t, gen)

	contentObj := &contentObject{
		Subject: coreIndexHL1,
		Properties: &propertiesType{
			Generator: ID,
			Resources: []*resource{
				{
					ID: fmt.Sprintf("%s:%s:%s", multihashPrefix, unpublishedLabel, suffix1),
				},
				{
					ID:             fmt.Sprintf("%s:%s:%s", multihashPrefix, parentMH1, suffix2),
					PreviousAnchor: parentHL1,
				},
			},
		},
	}

	witnessAnchorObj, err := vocab.NewAnchorObject(ID, vocab.MustUnmarshalToDoc([]byte(verifiableCred)))
	require.NoError(t, err)
	require.Len(t, witnessAnchorObj.URL(), 1)

	indexAnchorObj, err := vocab.NewAnchorObject(ID, vocab.MustMarshalToDoc(contentObj),
		vocab.WithLink(vocab.NewLink(witnessAnchorObj.URL()[0], vocab.RelationshipWitness)))
	require.NoError(t, err)
	require.Len(t, indexAnchorObj.URL(), 1)

	published := time.Now()

	t.Run("Success", func(t *testing.T) {
		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithAnchors(indexAnchorObj.URL()[0]),
			vocab.WithParent(testutil.MustParseURL(parentHL1)),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(witnessAnchorObj))),
			vocab.WithAttributedTo(testutil.MustParseURL(service1)),
			vocab.WithPublishedTime(&published),
		)

		payload, err := gen.CreatePayload(anchorEvent)
		require.NoError(t, err)
		require.NotNil(t, payload)

		require.Equal(t, coreIndexHL1, payload.CoreIndex)
		require.Equal(t, Namespace, payload.Namespace)
		require.Equal(t, Version, payload.Version)
		require.Equal(t, service1, payload.AnchorOrigin)
		require.Equal(t, published, *payload.Published)
		require.Equal(t, "", payload.PreviousAnchors[0].Anchor)
		require.Equal(t, "EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw", payload.PreviousAnchors[0].Suffix)
		require.Equal(t, parentHL1, payload.PreviousAnchors[1].Anchor)
		require.Equal(t, "EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw", payload.PreviousAnchors[1].Suffix)
	})

	t.Run("Core index anchor not found", func(t *testing.T) {
		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithAnchors(testutil.MustParseURL("hl:adsfwsds")),
			vocab.WithParent(testutil.MustParseURL(parentHL1)),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
			vocab.WithAttributedTo(testutil.MustParseURL(service1)),
			vocab.WithPublishedTime(&published),
		)

		payload, err := gen.CreatePayload(anchorEvent)
		require.Error(t, err)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, payload)
	})

	t.Run("No subject in content object", func(t *testing.T) {
		anchorObj, err := vocab.NewAnchorObject(ID, vocab.MustMarshalToDoc(&contentObject{}))
		require.NoError(t, err)
		require.Len(t, anchorObj.URL(), 1)

		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithAnchors(anchorObj.URL()[0]),
			vocab.WithParent(testutil.MustParseURL(parentHL1)),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(anchorObj))),
			vocab.WithAttributedTo(testutil.MustParseURL(service1)),
			vocab.WithPublishedTime(&published),
		)

		payload, err := gen.CreatePayload(anchorEvent)
		require.Error(t, err)
		require.Contains(t, err.Error(), "content object is missing subject")
		require.Nil(t, payload)
	})
}

const (
	//nolint:lll
	jsonContentObj = `{
  "properties": {
    "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
    "https://w3id.org/activityanchors#resources": [
      {
        "id": "did:orb:uAAA:EiDJpL-xeSE4kVgoGjaQm_OurMdR6jIeDRUxv7RhGNf5jw"
      },
      {
        "id": "did:orb:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA:EiAPcYpwgg88zOvQ4-sdwpj4UKqZeYS_Ej6kkZl_bZIJjw",
        "previousAnchor": "hl:uEiAuBQKPYXl90i3ho0aJsEGJpXCrvZvbRBtXH6RUF0rZLA"
      }
    ]
  },
  "subject": "hl:uEiCdYGN8IGTeXgsNjzf8THO6SD9SAtc9ithYE59iqgfkWg:uoQ-BeEJpcGZzOi8vYmFma3JlaWU1bWJyeHlpZGUzenBhd2RtcGc3NmV5NDUyamE3dmVhd3hod2ZucXdhdHQ1cmt1YjdlbGk"
}`

	verifiableCred = `{
  "@context": "https://www.w3.org/2018/credentials/v1",
  "type": "VerifiableCredential",
  "issuer": "https://sally.example.com/services/anchor",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
    "ID": "hl:uEiBy8pPgN9eS3hpQAwpSwJJvm6Awpsnc8kR_fkbUPotehg"
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
)
