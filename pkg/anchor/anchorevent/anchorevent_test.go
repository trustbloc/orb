/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	namespace = "did:orb"

	anchorOrigin = "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p"
	coreIndex    = "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95" //nolint:lll

	updateSuffix     = "uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA"
	updatePrevAnchor = "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5" //nolint:lll

	createSuffix = "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
)

func TestBuildAnchorEvent(t *testing.T) {
	previousAnchors := []*subject.SuffixAnchor{
		{Suffix: createSuffix},
		{Suffix: updateSuffix, Anchor: updatePrevAnchor},
	}

	publishedTime := time.Now()

	t.Run("success - mixed model (create + update)", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       namespace,
			Version:         0,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &publishedTime,
		}

		contentObj, err := BuildContentObject(payload)
		require.NoError(t, err)

		anchorEvent, err := BuildAnchorEvent(payload, contentObj.GeneratorID, contentObj.Payload,
			vocab.MustMarshalToDoc(&verifiable.Credential{}), vocab.GzipMediaType)
		require.NoError(t, err)

		require.Equal(t, anchorOrigin, anchorEvent.AttributedTo().String())
		require.NotNil(t, anchorEvent.Published())

		// check previous (one item since we have one create and one update)
		require.Equal(t, 1, len(anchorEvent.Parent()))
		require.Equal(t, updatePrevAnchor, anchorEvent.Parent()[0].String())

		// check attachment
		require.Equal(t, 2, len(anchorEvent.Attachment()))

		attachment := anchorEvent.Attachment()[0]
		require.True(t, attachment.Type().Is(vocab.TypeAnchorObject))

		anchorObject := attachment.AnchorObject()
		require.NotNil(t, anchorObject)

		require.NotNil(t, anchorObject.ContentObject())

		contentObjBytes, err := canonicalizer.MarshalCanonical(anchorObject.ContentObject())
		require.NoError(t, err)

		t.Logf("Content: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonContentObj), string(contentObjBytes))
	})

	t.Run("error - no previous anchors", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:    coreIndex,
			Namespace:    namespace,
			Version:      0,
			AnchorOrigin: anchorOrigin,
			Published:    &publishedTime,
		}

		_, err := BuildContentObject(payload)
		require.Error(t, err)
		require.Contains(t, err.Error(), "payload is missing previous anchors")
	})

	t.Run("success - two updates + create model", func(t *testing.T) {
		var anchorEvent *vocab.AnchorEventType

		err := json.Unmarshal([]byte(exampleAnchorEvent), &anchorEvent)
		require.NoError(t, err)

		require.NotNil(t, anchorEvent.Published)

		// check previous (two items - no create)
		require.Equal(t, 4, len(anchorEvent.Parent()))

		anchorObject, err := anchorEvent.AnchorObject(anchorEvent.Index())
		require.NoError(t, err)
		require.NotNil(t, anchorObject)

		require.NotNil(t, anchorObject.ContentObject())

		contentObjBytes, err := canonicalizer.MarshalCanonical(anchorObject.ContentObject())
		require.NoError(t, err)

		t.Logf("Content: %s", contentObjBytes)

		require.Equal(t, testutil.GetCanonical(t, jsonContentObj2), string(contentObjBytes))
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		invalidPayload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       "did:other",
			Version:         0,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &publishedTime,
			OperationCount:  uint64(len(previousAnchors)),
		}

		contentObj, err := BuildContentObject(invalidPayload)
		require.Error(t, err)
		require.Nil(t, contentObj)
		require.Contains(t, err.Error(), "generator not found for namespace [did:other] and version [0]")
	})
}

func TestGetPayloadFromActivity(t *testing.T) {
	previousAnchors := []*subject.SuffixAnchor{
		{Suffix: createSuffix},
		{Suffix: updateSuffix, Anchor: updatePrevAnchor},
	}

	publishedTime := time.Now()

	inPayload := &subject.Payload{
		CoreIndex:       coreIndex,
		Namespace:       namespace,
		Version:         0,
		AnchorOrigin:    anchorOrigin,
		PreviousAnchors: previousAnchors,
		Published:       &publishedTime,
		OperationCount:  uint64(len(previousAnchors)),
	}

	t.Run("success - from payload", func(t *testing.T) {
		contentObj, err := BuildContentObject(inPayload)
		require.NoError(t, err)

		anchorEvent, err := BuildAnchorEvent(inPayload, contentObj.GeneratorID, contentObj.Payload,
			vocab.MustMarshalToDoc(&verifiable.Credential{}), vocab.GzipMediaType)
		require.NoError(t, err)

		activityBytes, err := json.Marshal(anchorEvent)
		require.NoError(t, err)

		err = json.Unmarshal(activityBytes, &anchorEvent)
		require.NoError(t, err)

		outPayload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.NoError(t, err)

		require.Equal(t, inPayload.Namespace, outPayload.Namespace)
		require.Equal(t, inPayload.Version, outPayload.Version)
		require.Equal(t, inPayload.AnchorOrigin, outPayload.AnchorOrigin)
		require.Equal(t, inPayload.CoreIndex, outPayload.CoreIndex)
		require.Equal(t, inPayload.PreviousAnchors, outPayload.PreviousAnchors)
		require.Equal(t, inPayload.OperationCount, outPayload.OperationCount)
	})

	t.Run("error - missing anchor object", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
	})

	t.Run("error - invalid generator", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}
		err := json.Unmarshal([]byte(invalidAnchorEventGenerator), &anchorEvent)
		require.NoError(t, err)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "generator not found")
	})

	t.Run("error - invalid id", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}
		err := json.Unmarshal([]byte(invalidAnchorEventNoURN), &anchorEvent)
		require.NoError(t, err)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "failed to parse previous anchors from anchorEvent")
	})
}

const (
	//nolint:lll
	exampleAnchorEvent = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiBu_uYz6DWjy65dYQB4w7sr1LYP5K9-HCEDb74bHJq6aQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiCskiP5FXgmaq-cQUlsMMTRZgFLS6CQ-yZRTWDHPQk-SQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:EiBZ0gLKITQe2IYaCLJPjOzzszejFbzOtaNFzJF29uOL4A\",\"previousAnchor\":\"hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ\"},{\"id\":\"did:orb:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:EiAz8obk2MCsdqLq1trO4ubTYIsg3vlYaJdHKVR3wo3sGw\",\"previousAnchor\":\"hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAADCcZOeu_sgtkF2JSWuwvc7LEw4u24Pfi1d5_0APl3Q\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiA6WSQ_2y2vcyakXW24vZk3Q45KMGIE4AL_2S2Hyz9VXw\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAOaoQzphgwqX_PNBDSYDhwgu_3Q63hPZqEYio9tmfFCg\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiDMQfIzZFztRMNzTanIY5VoDcRr_zGA5SV0pNuDIDF47w\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"}]},\"subject\":\"hl:uEiAjb4i-wvE5w-pdE-WdX-aecG_Vd30HIvArHVdjjeqVUw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWpiNGktd3ZFNXctcGRFLVdkWC1hZWNHX1ZkMzBISXZBckhWZGpqZXFWVXc\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ\",\"id\":\"https://orb.domain2.com/vc/204c06b0-89d9-496d-9148-233e138ed745\",\"issuanceDate\":\"2022-02-10T18:02:13.530381545Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":{\"created\":\"2022-02-10T18:02:13.530557527Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..w6zwingj2NvResa6elVbYxLv6c_jMTo_9zPY0T9po0MekuWRJCBDlYIR3ESYUdAEpnH1iYQ3_gYT-VMioNZtCw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ",
  "parent": [
    "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRG56MUZIbzhmRHN5ZE1lU18tYnFkNVQwNXRHRXNueXRHUUVpaF9kMVJRT3d4QmlwZnM6Ly9iYWZrcmVpaGh6NWl1cGk2aHlvenNvdGR6Zjc3ZzVqM3pqNWhnMmdjbGU3Zm5kZWFzZmI3eG92Y3FobQ",
    "hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVFNTy1oNV94T3kwaWcwbE9UeHVxMnVXeFBCY1FWcmtwMEVKY3A2OWtyY1F4QmlwZnM6Ly9iYWZrcmVpYXFnZHgyZHo3NGozZnVyaWdza29qNG4ydnd4ZndlNmJvZWN3eGV1NWFxczR1Nnh3amxvZQ",
    "hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ3Y3STRrSGNNeS1JNmJ3YlJJZmZPSjE5U2xvaS0zdmw0cTkzUGIwUndKTXc",
    "hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpRHJsNUt4aVRlX0VHb3Y1ZEhldG1PMnVKT1R0SWZjS0E5UE1OZ21kR1RZaXc"
  ],
  "published": "2022-02-10T18:02:13.515820672Z",
  "type": "AnchorEvent"
}`

	//nolint:lll
	invalidAnchorEventNoURN = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiBu_uYz6DWjy65dYQB4w7sr1LYP5K9-HCEDb74bHJq6aQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiCskiP5FXgmaq-cQUlsMMTRZgFLS6CQ-yZRTWDHPQk-SQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:EiBZ0gLKITQe2IYaCLJPjOzzszejFbzOtaNFzJF29uOL4A\",\"previousAnchor\":\"hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ\"},{\"id\":\"did:orb:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:EiAz8obk2MCsdqLq1trO4ubTYIsg3vlYaJdHKVR3wo3sGw\",\"previousAnchor\":\"hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAADCcZOeu_sgtkF2JSWuwvc7LEw4u24Pfi1d5_0APl3Q\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiA6WSQ_2y2vcyakXW24vZk3Q45KMGIE4AL_2S2Hyz9VXw\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAOaoQzphgwqX_PNBDSYDhwgu_3Q63hPZqEYio9tmfFCg\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiDMQfIzZFztRMNzTanIY5VoDcRr_zGA5SV0pNuDIDF47w\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"}]},\"subject\":\"hl:uEiAjb4i-wvE5w-pdE-WdX-aecG_Vd30HIvArHVdjjeqVUw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWpiNGktd3ZFNXctcGRFLVdkWC1hZWNHX1ZkMzBISXZBckhWZGpqZXFWVXc\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ\",\"id\":\"https://orb.domain2.com/vc/204c06b0-89d9-496d-9148-233e138ed745\",\"issuanceDate\":\"2022-02-10T18:02:13.530381545Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":{\"created\":\"2022-02-10T18:02:13.530557527Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..w6zwingj2NvResa6elVbYxLv6c_jMTo_9zPY0T9po0MekuWRJCBDlYIR3ESYUdAEpnH1iYQ3_gYT-VMioNZtCw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},\"type\":\"VerifiableCredential\"}",
      "generator": "https://w3id.org/orb#v0",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ",
  "published": "2022-02-10T18:02:13.515820672Z",
  "type": "AnchorEvent"
}`

	//nolint:lll
	invalidAnchorEventGenerator = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/activityanchors/v1"
  ],
  "attachment": [
    {
      "content": "{\"properties\":{\"https://w3id.org/activityanchors#generator\":\"https://w3id.org/orb#v0\",\"https://w3id.org/activityanchors#resources\":[{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiBu_uYz6DWjy65dYQB4w7sr1LYP5K9-HCEDb74bHJq6aQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiCskiP5FXgmaq-cQUlsMMTRZgFLS6CQ-yZRTWDHPQk-SQ\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:EiBZ0gLKITQe2IYaCLJPjOzzszejFbzOtaNFzJF29uOL4A\",\"previousAnchor\":\"hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ\"},{\"id\":\"did:orb:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:EiAz8obk2MCsdqLq1trO4ubTYIsg3vlYaJdHKVR3wo3sGw\",\"previousAnchor\":\"hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAADCcZOeu_sgtkF2JSWuwvc7LEw4u24Pfi1d5_0APl3Q\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiA6WSQ_2y2vcyakXW24vZk3Q45KMGIE4AL_2S2Hyz9VXw\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"},{\"id\":\"did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAOaoQzphgwqX_PNBDSYDhwgu_3Q63hPZqEYio9tmfFCg\",\"previousAnchor\":\"hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw\"},{\"id\":\"did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiDMQfIzZFztRMNzTanIY5VoDcRr_zGA5SV0pNuDIDF47w\",\"previousAnchor\":\"hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw\"}]},\"subject\":\"hl:uEiAjb4i-wvE5w-pdE-WdX-aecG_Vd30HIvArHVdjjeqVUw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWpiNGktd3ZFNXctcGRFLVdkWC1hZWNHX1ZkMzBISXZBckhWZGpqZXFWVXc\"}",
      "mediaType": "application/json",
      "tag": [
        {
          "href": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg",
          "rel": [
            "witness"
          ],
          "type": "Link"
        }
      ],
      "type": "AnchorObject",
      "url": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ"
    },
    {
      "content": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":\"hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ\",\"id\":\"https://orb.domain2.com/vc/204c06b0-89d9-496d-9148-233e138ed745\",\"issuanceDate\":\"2022-02-10T18:02:13.530381545Z\",\"issuer\":\"https://orb.domain2.com\",\"proof\":{\"created\":\"2022-02-10T18:02:13.530557527Z\",\"domain\":\"https://orb.domain2.com\",\"jws\":\"eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..w6zwingj2NvResa6elVbYxLv6c_jMTo_9zPY0T9po0MekuWRJCBDlYIR3ESYUdAEpnH1iYQ3_gYT-VMioNZtCw\",\"proofPurpose\":\"assertionMethod\",\"type\":\"Ed25519Signature2018\",\"verificationMethod\":\"did:web:orb.domain2.com#orb2key\"},\"type\":\"VerifiableCredential\"}",
      "mediaType": "application/json",
      "type": "AnchorObject",
      "url": "hl:uEiD6H3nMnJDB6WJ2evunRbjyb6R9t2yGwGB7p3g3RUUHRg"
    }
  ],
  "attributedTo": "https://orb.domain2.com/services/orb",
  "index": "hl:uEiBwvdpyXrDOZzEyVNnfaw793ditWQtG_4U72dkReHe4fQ",
  "parent": [
    "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpRG56MUZIbzhmRHN5ZE1lU18tYnFkNVQwNXRHRXNueXRHUUVpaF9kMVJRT3d4QmlwZnM6Ly9iYWZrcmVpaGh6NWl1cGk2aHlvenNvdGR6Zjc3ZzVqM3pqNWhnMmdjbGU3Zm5kZWFzZmI3eG92Y3FobQ",
    "hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQVFNTy1oNV94T3kwaWcwbE9UeHVxMnVXeFBCY1FWcmtwMEVKY3A2OWtyY1F4QmlwZnM6Ly9iYWZrcmVpYXFnZHgyZHo3NGozZnVyaWdza29qNG4ydnd4ZndlNmJvZWN3eGV1NWFxczR1Nnh3amxvZQ",
    "hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQ3Y3STRrSGNNeS1JNmJ3YlJJZmZPSjE5U2xvaS0zdmw0cTkzUGIwUndKTXc",
    "hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpRHJsNUt4aVRlX0VHb3Y1ZEhldG1PMnVKT1R0SWZjS0E5UE1OZ21kR1RZaXc"
  ],
  "published": "2022-02-10T18:02:13.515820672Z",
  "type": "AnchorEvent"
}`

	//nolint:lll
	jsonContentObj = `{
  "properties": {
    "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
    "https://w3id.org/activityanchors#resources": [
      {
        "id": "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
      },
      {
        "id": "did:orb:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
        "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
      }
    ]
  },
  "subject": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95"
}`

	//nolint:lll
	jsonContentObj2 = `{
  "properties": {
    "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v0",
    "https://w3id.org/activityanchors#resources": [
      {
        "id": "did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiBu_uYz6DWjy65dYQB4w7sr1LYP5K9-HCEDb74bHJq6aQ",
        "previousAnchor": "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw"
      },
      {
        "id": "did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiCskiP5FXgmaq-cQUlsMMTRZgFLS6CQ-yZRTWDHPQk-SQ",
        "previousAnchor": "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw"
      },
      {
        "id": "did:orb:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ:EiBZ0gLKITQe2IYaCLJPjOzzszejFbzOtaNFzJF29uOL4A",
        "previousAnchor": "hl:uEiAQMO-h5_xOy0ig0lOTxuq2uWxPBcQVrkp0EJcp69krcQ"
      },
      {
        "id": "did:orb:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw:EiAz8obk2MCsdqLq1trO4ubTYIsg3vlYaJdHKVR3wo3sGw",
        "previousAnchor": "hl:uEiCv7I4kHcMy-I6bwbRIffOJ19Sloi-3vl4q93Pb0RwJMw"
      },
      {
        "id": "did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAADCcZOeu_sgtkF2JSWuwvc7LEw4u24Pfi1d5_0APl3Q",
        "previousAnchor": "hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw"
      },
      {
        "id": "did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiA6WSQ_2y2vcyakXW24vZk3Q45KMGIE4AL_2S2Hyz9VXw",
        "previousAnchor": "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw"
      },
      {
        "id": "did:orb:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw:EiAOaoQzphgwqX_PNBDSYDhwgu_3Q63hPZqEYio9tmfFCg",
        "previousAnchor": "hl:uEiDrl5KxiTe_EGov5dHetmO2uJOTtIfcKA9PMNgmdGTYiw"
      },
      {
        "id": "did:orb:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw:EiDMQfIzZFztRMNzTanIY5VoDcRr_zGA5SV0pNuDIDF47w",
        "previousAnchor": "hl:uEiDnz1FHo8fDsydMeS_-bqd5T05tGEsnytGQEih_d1RQOw"
      }
    ]
  },
  "subject": "hl:uEiAjb4i-wvE5w-pdE-WdX-aecG_Vd30HIvArHVdjjeqVUw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQWpiNGktd3ZFNXctcGRFLVdkWC1hZWNHX1ZkMzBISXZBckhWZGpqZXFWVXc"
}`
)
