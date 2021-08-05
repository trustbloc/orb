/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/subject"
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

func TestBuildActivityFromPayload(t *testing.T) {
	previousAnchors := make(map[string]string)
	previousAnchors[createSuffix] = ""
	previousAnchors[updateSuffix] = updatePrevAnchor

	t.Run("success - mixed model (create + update)", func(t *testing.T) {
		payload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       namespace,
			Version:         1,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		}
		activity, err := BuildActivityFromPayload(payload)
		require.NoError(t, err)

		require.Equal(t, anchorEventType, activity.Type)
		require.Equal(t, anchorOrigin, activity.AttributedTo)
		require.NotNil(t, activity.Published)

		// check previous (one item since we have one create and one update)
		require.Equal(t, 1, len(activity.Parent))
		require.Equal(t, updatePrevAnchor, activity.Parent[0])

		// check attachment
		require.Equal(t, 1, len(activity.Attachment))

		require.Equal(t, coreIndex, activity.Attachment[0].URL)
		require.Equal(t, anchorIndexType, activity.Attachment[0].Type)
		require.Equal(t, "https://w3id.org/orb#v1", activity.Attachment[0].Generator)
		require.Equal(t, 2, len(activity.Attachment[0].Resources))

		expectedResource := Resource{
			ID:             multihashPrefix + ":" + updateSuffix,
			PreviousAnchor: updatePrevAnchorID,
			Type:           anchorResourceType,
		}

		for _, obj := range activity.Attachment[0].Resources {
			switch obj.(type) {
			case string:
				require.Equal(t, multihashPrefix+multihashPrefixDelimiter+createSuffix, obj)
			case Resource:
				require.Equal(t, expectedResource, obj)
			default:
				require.Fail(t, "unexpected object type for resource")
			}
		}
	})

	t.Run("success - two updates + create model", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(exampleActivity), &activity)
		require.NoError(t, err)

		require.Equal(t, "AnchorEvent", activity.Type)
		require.Equal(t, anchorEventType, activity.Type)
		require.NotNil(t, activity.Published)

		// check previous (two items - no create)
		require.Equal(t, 2, len(activity.Parent))

		require.Equal(t, anchorIndexType, activity.Attachment[0].Type)
		require.Equal(t, "https://w3id.org/orb#v1", activity.Attachment[0].Generator)
		require.Equal(t, 3, len(activity.Attachment[0].Resources))
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		invalidPayload := &subject.Payload{
			CoreIndex:       coreIndex,
			Namespace:       "did:other",
			Version:         1,
			AnchorOrigin:    anchorOrigin,
			PreviousAnchors: previousAnchors,
			Published:       &util.TimeWithTrailingZeroMsec{Time: time.Now()},
			OperationCount:  uint64(len(previousAnchors)),
		}

		activity, err := BuildActivityFromPayload(invalidPayload)
		require.Error(t, err)
		require.Nil(t, activity)
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
			Published:       &util.TimeWithTrailingZeroMsec{Time: time.Now()},
			OperationCount:  uint64(len(previousAnchors)),
		}

		activity, err := BuildActivityFromPayload(invalidPayload)
		require.Error(t, err)
		require.Nil(t, activity)
		require.Contains(t, err.Error(),
			"invalid previous anchor hashlink[uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg] - must contain separator ':'")
	})
}

func TestGetPayloadFromActivity(t *testing.T) {
	previousAnchors := make(map[string]string)
	previousAnchors[createSuffix] = ""
	previousAnchors[updateSuffix] = updatePrevAnchor

	inPayload := &subject.Payload{
		CoreIndex:       coreIndex,
		Namespace:       namespace,
		Version:         1,
		AnchorOrigin:    anchorOrigin,
		PreviousAnchors: previousAnchors,
		Published:       &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		OperationCount:  uint64(len(previousAnchors)),
	}

	t.Run("success - from payload", func(t *testing.T) {
		activity, err := BuildActivityFromPayload(inPayload)
		require.NoError(t, err)

		activityBytes, err := json.Marshal(activity)
		require.NoError(t, err)

		err = json.Unmarshal(activityBytes, &activity)
		require.NoError(t, err)

		outPayload, err := GetPayloadFromActivity(activity)
		require.NoError(t, err)

		require.Equal(t, inPayload.Namespace, outPayload.Namespace)
		require.Equal(t, inPayload.Version, outPayload.Version)
		require.Equal(t, inPayload.AnchorOrigin, outPayload.AnchorOrigin)
		require.Equal(t, inPayload.CoreIndex, outPayload.CoreIndex)
		require.Equal(t, inPayload.PreviousAnchors, outPayload.PreviousAnchors)
		require.Equal(t, inPayload.OperationCount, outPayload.OperationCount)
	})

	t.Run("error - missing attachment", func(t *testing.T) {
		activity := Activity{}

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "activity is missing attachment")
	})

	t.Run("error - namespace not supported", func(t *testing.T) {
		activity := Activity{
			Attachment: []Attachment{{Generator: "invalid-generator"}},
		}

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse namespace and version from activity generator: invalid namespace and version format")
	})

	t.Run("error - activity is missing attachment URL", func(t *testing.T) {
		activity := Activity{
			Attachment: []Attachment{{Generator: "https://w3id.org/orb#v1"}},
		}

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(), "activity is missing attachment URL")
	})

	t.Run("error - invalid id", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoURN), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: id has to start with did:orb:uAAA:")
	})

	t.Run("error - resource not found in previous links", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoResourceInPrevious), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: resource[hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg] not found in previous anchor list") //nolint:lll
	})

	t.Run("error - unexpected type for resource", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityIntTypeForResource), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: unexpected object type 'float64' for resource")
	})

	t.Run("error - no id for resource", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoIDInResource), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: failed to get resource from map: missing value for key[id]")
	})

	t.Run("error - no previous anchor for resource", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoPreviousAnchorInResource), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: failed to get resource from map: missing value for key[previousAnchor]") //nolint:lll
	})

	t.Run("error - no type for resource", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoTypeInResource), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: failed to get resource from map: missing value for key[type]")
	})

	t.Run("error - wrong type for resource id", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityIDInResourceNotAString), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: failed to get resource from map: value[float64] for key[id] is not a string") //nolint:lll
	})
}

//nolint:lll
var exampleActivity = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
          "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
        }
      ]
    },
    {
      "type": "AnchorObject",
      "url": "hl:uEiCrkp_NVZQDeWB5LqC5jK9f2va2BkXk7ySMKNt0Jg85Pg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlDcmtwX05WWlFEZVdCNUxxQzVqSzlmMnZhMkJrWGs3eVNNS050MEpnODVQZ3hCaXBmczovL2JhZmtyZWlmbHNrcDQydm11YW40d2E2am91YzR5emwyNzNsM2xtYnNmNHR4c2pkYmkzbjJjbWR6emh5"
    }
  ]
}
`

//nolint:lll
var invalidActivityIntTypeForResource = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
  		123
      ]
    }
  ]
}
`

//nolint:lll
var invalidActivityNoURN = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
      ]
    }
  ]
}
`

//nolint:lll
var invalidActivityNoResourceInPrevious = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
          "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
        }
      ]
    },
    {
      "type": "AnchorObject",
      "url": "hl:uEiCrkp_NVZQDeWB5LqC5jK9f2va2BkXk7ySMKNt0Jg85Pg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlDcmtwX05WWlFEZVdCNUxxQzVqSzlmMnZhMkJrWGs3eVNNS050MEpnODVQZ3hCaXBmczovL2JhZmtyZWlmbHNrcDQydm11YW40d2E2am91YzR5emwyNzNsM2xtYnNmNHR4c2pkYmkzbjJjbWR6emh5"
    }
  ]
}`

//nolint:lll
var invalidActivityIDInResourceNotAString = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "type": "AnchorResource",
          "id": 1234,
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
          "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
        }
      ]
    },
    {
      "type": "AnchorObject",
      "url": "hl:uEiCrkp_NVZQDeWB5LqC5jK9f2va2BkXk7ySMKNt0Jg85Pg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlDcmtwX05WWlFEZVdCNUxxQzVqSzlmMnZhMkJrWGs3eVNNS050MEpnODVQZ3hCaXBmczovL2JhZmtyZWlmbHNrcDQydm11YW40d2E2am91YzR5emwyNzNsM2xtYnNmNHR4c2pkYmkzbjJjbWR6emh5"
    }
  ]
}`

//nolint:lll
var invalidActivityNoIDInResource = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
        }
      ]
    }
  ]
}`

//nolint:lll
var invalidActivityNoPreviousAnchorInResource = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo"
        }
      ]
    }
  ]
}`

//nolint:lll
var invalidActivityNoTypeInResource = `
{
  "type": "AnchorEvent",
  "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
  "published": "2021-01-27T09:30:00Z",
  "parent": [
    "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3hCaXBmczovL2JhZmtyZWlibXJtZW51eGhnYW9tb2Q0bTI2ZHM1enRkdWp4emhqb2JndnBzeWwydjJuZGNza3EyaWF5",
    "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBbjNZN1VTb1BfbE5WWC1mMEVFdTFhakx5bW5xQkpJdGlNQVJoS0J6QUtXZ3hCaXBmczovL2JhZmtyZWliaDN3aG5pc3VkNzZrbmt2N3o3dWNiZjNrMnJzNmtuaHZhamVybnJkYWJkYmZhb21ha2xp"
  ],
  "attachment": [
    {
      "type": "AnchorIndex",
      "generator": "https://w3id.org/orb#v1",
      "url": "hl:uEiD2k2kSGESB9e3UwwTOJ8WhqCeAT8fzKfQ9JzuGIYcHdg:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlEMmsya1NHRVNCOWUzVXd3VE9KOFdocUNlQVQ4ZnpLZlE5Snp1R0lZY0hkZ3hCaXBmczovL2JhZmtyZWlod3NudXJlZ2NlcWgyNjN2Z2RhdGhjcHJuYnZhdHlhdDZoNm11N2lwamhob2RjZGJ5aG95",
      "resources": [
        "did:orb:uAAA:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
        {
          "id": "did:orb:uAAA:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
          "previousAnchor": "hl:uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg"
        },
        {
          "type": "AnchorResource",
          "id": "did:orb:uAAA:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
          "previousAnchor": "hl:uEiAn3Y7USoP_lNVX-f0EEu1ajLymnqBJItiMARhKBzAKWg"
        }
      ]
    }
  ]
}`
