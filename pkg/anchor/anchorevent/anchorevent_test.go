/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	namespace = "did:orb"

	anchorOrigin = "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p"
	coreIndex    = "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95" //nolint:lll

	updateSuffix       = "uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA"
	updatePrevAnchorID = "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
	updatePrevAnchor   = "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5" //nolint:lll

	createSuffix = "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
)

func TestBuildAnchorEvent(t *testing.T) {
	previousAnchors := make(map[string]string)
	previousAnchors[createSuffix] = ""
	previousAnchors[updateSuffix] = updatePrevAnchor

	publishedTime := time.Now()

	t.Run("success - mixed model (create + update)", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       namespace,
			Version:         1,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &publishedTime,
		}

		contentObj, err := BuildContentObject(payload)
		require.NoError(t, err)

		anchorEvent, err := BuildAnchorEvent(payload, contentObj, &verifiable.Credential{})
		require.NoError(t, err)

		require.Equal(t, anchorOrigin, anchorEvent.AttributedTo().String())
		require.NotNil(t, anchorEvent.Published())

		// check previous (one item since we have one create and one update)
		require.Equal(t, 1, len(anchorEvent.Parent()))
		require.Equal(t, updatePrevAnchor, anchorEvent.Parent()[0].String())

		// check attachment
		require.Equal(t, 1, len(anchorEvent.Attachment()))

		attachment := anchorEvent.Attachment()[0]
		require.True(t, attachment.Type().Is(vocab.TypeAnchorObject))

		anchorObject := attachment.AnchorObject()
		require.NotNil(t, anchorObject)

		require.NotNil(t, anchorObject.ContentObject())

		require.Equal(t, "https://w3id.org/orb#v1", anchorObject.ContentObject().Generator())
		require.Len(t, anchorObject.ContentObject().Resources(), 2)

		for _, res := range anchorObject.ContentObject().Resources() {
			switch res.ID {
			case multihashPrefix + multihashPrefixDelimiter + createSuffix:
				require.Empty(t, res.PreviousAnchor)

			case multihashPrefix + multihashPrefixDelimiter + updateSuffix:
				require.Equal(t, updatePrevAnchorID, res.PreviousAnchor)

			default:
				t.Fatalf("unexpected resource [%s]", res.ID)
			}
		}
	})

	t.Run("success - two updates + create model", func(t *testing.T) {
		var anchorEvent *vocab.AnchorEventType

		err := json.Unmarshal([]byte(exampleAnchorEvent), &anchorEvent)
		require.NoError(t, err)

		require.NotNil(t, anchorEvent.Published)

		// check previous (two items - no create)
		require.Equal(t, 2, len(anchorEvent.Parent()))

		require.Equal(t, 1, len(anchorEvent.Attachment()))

		attachment := anchorEvent.Attachment()[0]
		require.True(t, attachment.Type().Is(vocab.TypeAnchorObject))

		anchorObject := attachment.AnchorObject()
		require.NotNil(t, anchorObject)

		require.NotNil(t, anchorObject.ContentObject())

		require.Equal(t, "https://w3id.org/orb#v1", anchorObject.ContentObject().Generator())
		require.Len(t, anchorObject.ContentObject().Resources(), 3)
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		invalidPayload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       "did:other",
			Version:         1,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &publishedTime,
			OperationCount:  uint64(len(previousAnchors)),
		}

		contentObj, err := BuildContentObject(invalidPayload)
		require.Error(t, err)
		require.Nil(t, contentObj)
		require.Contains(t, err.Error(), "generator not defined for namespace: did:other")
	})

	t.Run("error - invalid previous anchor hashlink", func(t *testing.T) {
		previousAnchors := make(map[string]string)
		previousAnchors[createSuffix] = ""
		previousAnchors[updateSuffix] = "uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"

		invalidPayload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       "did:orb",
			Version:         1,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &publishedTime,
			OperationCount:  uint64(len(previousAnchors)),
		}

		contentObj, err := BuildContentObject(invalidPayload)
		require.Error(t, err)
		require.Nil(t, contentObj)
		require.Contains(t, err.Error(),
			"invalid previous anchor hashlink[uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg] - must contain separator ':'")
	})
}

func TestGetPayloadFromActivity(t *testing.T) {
	previousAnchors := make(map[string]string)
	previousAnchors[createSuffix] = ""
	previousAnchors[updateSuffix] = updatePrevAnchor

	publishedTime := time.Now()

	inPayload := &subject.Payload{
		CoreIndex:       coreIndex,
		Namespace:       namespace,
		Version:         1,
		AnchorOrigin:    anchorOrigin,
		PreviousAnchors: previousAnchors,
		Published:       &publishedTime,
		OperationCount:  uint64(len(previousAnchors)),
	}

	t.Run("success - from payload", func(t *testing.T) {
		contentObj, err := BuildContentObject(inPayload)
		require.NoError(t, err)

		anchorEvent, err := BuildAnchorEvent(inPayload, contentObj, &verifiable.Credential{})
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

	t.Run("error - missing attachment", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "anchor event is missing attachment")
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		contentObj := vocab.NewContentObject("invalid-generator",
			testutil.MustParseURL(
				"hl:uEiB1miJeUsG7PiLvFel8DKoluzDVl3OnpjKgAGZS588PXQ:uoQ-BeEJpcGZzOi8vYmFma3JlaWR2dGlyZjR1d2J4bTdjZjN5djVmNmF6a3JmeG15bmxmM3R1NnRkZmlhYW16am9wdHlwbHU", //nolint:lll
			))

		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithAttachment(
				vocab.NewObjectProperty(
					vocab.WithAnchorObject(
						vocab.NewAnchorObject(contentObj, nil),
					),
				),
			),
		)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "invalid namespace and version format")
	})

	t.Run("error - anchor event is missing subject (anchor index)", func(t *testing.T) {
		contentObj := vocab.NewContentObject("https://w3id.org/orb#v1", nil)

		anchorEvent := vocab.NewAnchorEvent(
			vocab.WithAttachment(
				vocab.NewObjectProperty(
					vocab.WithAnchorObject(
						vocab.NewAnchorObject(contentObj, nil),
					),
				),
			),
		)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "anchor event content object is missing subject")
	})

	t.Run("error - invalid id", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}
		err := json.Unmarshal([]byte(invalidAnchorEventNoURN), &anchorEvent)
		require.NoError(t, err)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from anchorEvent: id has to start with did:orb:uAAA:")
	})

	t.Run("error - resource not found in previous links", func(t *testing.T) {
		anchorEvent := &vocab.AnchorEventType{}
		err := json.Unmarshal([]byte(invalidAnchorEventNoResourceInPrevious), anchorEvent)
		require.NoError(t, err)

		payload, err := GetPayloadFromAnchorEvent(anchorEvent)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "not found in previous anchor list")
	})
}

//nolint:lll
var exampleAnchorEvent = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v1",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uAAA:EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
            },
            {
              "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
              "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
            },
            {
              "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
              "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
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
  "type": "Info",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`

//nolint:lll
var invalidAnchorEventNoURN = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v1",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "EiD6mH7iCLGjm9mhBr2TP_5_vRz6nyLYZ5E74xbZzrlmLg"
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
  "type": "Info",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`

//nolint:lll
var invalidAnchorEventNoResourceInPrevious = `{
  "@context": "https://w3id.org/activityanchors/v1",
  "anchors": "hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w",
  "attachment": [
    {
      "contentObject": {
        "properties": {
          "https://w3id.org/activityanchors#generator": "https://w3id.org/orb#v1",
          "https://w3id.org/activityanchors#resources": [
            {
              "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
              "previousAnchor": "hl:uEiAs3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
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
  "type": "Info",
  "url": "hl:uEiCJWrCq8ttsWob5UVueRQiQ_QUrocJY6ZA8BDgzgakuhg:uoQ-BeEJpcGZzOi8vYmFma3JlaWVqbGt5a3Y0dzNucm5pbjZrcmxvcGVrY2VxN3Vjc3hpb2NsZHV6YXBhZWhhenlka2pvcXk"
}`
