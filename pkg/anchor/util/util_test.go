/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const defVCContext = "https://www.w3.org/2018/credentials/v1"

func TestVerifiableCredentialFromAnchorEvent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousAnchors,
		}

		contentObj, err := anchorevent.BuildContentObject(payload)
		require.NoError(t, err)

		contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
		require.NoError(t, err)

		hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
		require.NoError(t, err)

		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: &builder.CredentialSubject{ID: hl},
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWrapper{Time: time.Now()},
		}

		vcDoc, err := vocab.MarshalToDoc(vc)
		require.NoError(t, err)

		act, err := anchorevent.BuildAnchorEvent(payload, contentObj.GeneratorID, contentObj.Payload, vcDoc)
		require.NoError(t, err)

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		vc2, err := VerifiableCredentialFromAnchorEvent(act, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		vc2Bytes, err := vc2.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, vcBytes, vc2Bytes)
	})

	t.Run("Invalid anchor event", func(t *testing.T) {
		act := vocab.NewAnchorEvent()

		vc, err := VerifiableCredentialFromAnchorEvent(act, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid anchor event")
		require.Nil(t, vc)
	})

	t.Run("GetWitness error", func(t *testing.T) {
		doc, err := vocab.UnmarshalToDoc([]byte(`{}`))
		require.NoError(t, err)

		indexAnchorObj, err := vocab.NewAnchorObject("some-generator", doc)
		require.NoError(t, err)

		act := vocab.NewAnchorEvent(
			vocab.WithAnchors(indexAnchorObj.URL()[0]),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		)

		_, err = VerifiableCredentialFromAnchorEvent(act, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not contain a 'tag' field")
	})
}

func TestGetWitnessDoc(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "coreIndex",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousAnchors,
		}

		contentObj, err := anchorevent.BuildContentObject(payload)
		require.NoError(t, err)

		contentObjBytes, err := canonicalizer.MarshalCanonical(contentObj)
		require.NoError(t, err)

		hl, err := hashlink.New().CreateHashLink(contentObjBytes, nil)
		require.NoError(t, err)

		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: &builder.CredentialSubject{ID: hl},
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWrapper{Time: time.Now()},
		}

		vcDoc, err := vocab.MarshalToDoc(vc)
		require.NoError(t, err)

		act, err := anchorevent.BuildAnchorEvent(payload, contentObj.GeneratorID, contentObj.Payload, vcDoc)
		require.NoError(t, err)

		vcDoc, err = GetWitnessDoc(act)
		require.NoError(t, err)

		vc2Bytes, err := json.Marshal(vcDoc)
		require.NoError(t, err)

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, vcBytes, vc2Bytes)
	})

	t.Run("No tag in index anchor object", func(t *testing.T) {
		doc, err := vocab.UnmarshalToDoc([]byte(`{}`))
		require.NoError(t, err)

		indexAnchorObj, err := vocab.NewAnchorObject("some-generator", doc)
		require.NoError(t, err)

		ae := vocab.NewAnchorEvent(
			vocab.WithAnchors(indexAnchorObj.URL()[0]),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		)

		_, err = GetWitnessDoc(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not contain a 'tag' field")
	})

	t.Run("No tag field of type witness", func(t *testing.T) {
		doc, err := vocab.UnmarshalToDoc([]byte(`{}`))
		require.NoError(t, err)

		indexAnchorObj, err := vocab.NewAnchorObject("some-generator", doc,
			vocab.WithLink(vocab.NewLink(testutil.MustParseURL("hl:uEiCYs2XYno8FGuqzbiQ6gBrg_hqpELV9pJaUA75Y0mATRw"),
				"some-relationship")))
		require.NoError(t, err)

		ae := vocab.NewAnchorEvent(
			vocab.WithAnchors(indexAnchorObj.URL()[0]),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		)

		_, err = GetWitnessDoc(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not contain a tag of type 'Link' and 'rel' 'witness'")
	})

	t.Run("Index not found", func(t *testing.T) {
		doc, err := vocab.UnmarshalToDoc([]byte(`{}`))
		require.NoError(t, err)

		indexAnchorObj, err := vocab.NewAnchorObject("some-generator", doc,
			vocab.WithLink(vocab.NewLink(testutil.MustParseURL("hl:uEiCYs2XYno8FGuqzbiQ6gBrg_hqpELV9pJaUA75Y0mATRw"),
				vocab.RelationshipWitness)))
		require.NoError(t, err)

		ae := vocab.NewAnchorEvent(
			vocab.WithAnchors(testutil.MustParseURL("hl:uEiB7dnp4KR_LmSO_IqXMUquZzXuOEov9UzML-YoRWTZrrw")),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		)

		_, err = GetWitnessDoc(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), "content not found")
	})

	t.Run("Witness not found", func(t *testing.T) {
		doc, err := vocab.UnmarshalToDoc([]byte(`{}`))
		require.NoError(t, err)

		indexAnchorObj, err := vocab.NewAnchorObject("some-generator", doc,
			vocab.WithLink(vocab.NewLink(testutil.MustParseURL("hl:uEiCYs2XYno8FGuqzbiQ6gBrg_hqpELV9pJaUA75Y0mATRw"),
				vocab.RelationshipWitness)))
		require.NoError(t, err)

		ae := vocab.NewAnchorEvent(
			vocab.WithAnchors(indexAnchorObj.URL()[0]),
			vocab.WithAttachment(vocab.NewObjectProperty(vocab.WithAnchorObject(indexAnchorObj))),
		)

		_, err = GetWitnessDoc(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found in anchor event")
	})
}
