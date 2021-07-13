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
	coreIndex    = "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

	updateSuffix     = "uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA"
	updatePrevAnchor = "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu"
	createSuffix     = "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
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
		require.Equal(t, 1, len(activity.Previous))
		require.Equal(t, linkType, activity.Previous[0].Type)
		require.Equal(t, multihashPrefix+":"+updatePrevAnchor, activity.Previous[0].ID)
		require.Equal(t, updatePrevAnchor, activity.Previous[0].URL)

		// check attachment
		require.Equal(t, 1, len(activity.Attachment))

		expectedURL := Link{
			Href: coreIndex,
			Type: "Link",
			Rel:  "self",
		}

		require.Equal(t, expectedURL, activity.Attachment[0].URL[0])
		require.Equal(t, anchorIndexType, activity.Attachment[0].Type)
		require.Equal(t, "https://w3id.org/orb#v1", activity.Attachment[0].Generator)
		require.Equal(t, 2, len(activity.Attachment[0].Resources))

		expectedResource := Resource{
			ID:             multihashPrefix + ":" + updateSuffix,
			PreviousAnchor: multihashPrefix + ":" + updatePrevAnchor,
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

		err := json.Unmarshal([]byte(testAdditionalSample), &activity)
		require.NoError(t, err)

		require.Equal(t, "AnchorEvent", activity.Type)
		require.Equal(t, anchorEventType, activity.Type)
		require.NotNil(t, activity.Published)

		// check previous (two items - no create)
		require.Equal(t, 2, len(activity.Previous))
		require.Equal(t, linkType, activity.Previous[0].Type)

		require.Equal(t, anchorIndexType, activity.Attachment[0].Type)
		require.Equal(t, "https://example.com/spec#v1", activity.Attachment[0].Generator)
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

	t.Run("success - from JSON", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(testActivityWithCreate), &activity)
		require.NoError(t, err)

		outPayload, err := GetPayloadFromActivity(&activity)
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
			"failed to parse previous anchors from activity: id has to start with urn:multihash:")
	})

	t.Run("error - resource not found in previous links", func(t *testing.T) {
		var activity Activity

		err := json.Unmarshal([]byte(invalidActivityNoResourceInPrevious), &activity)
		require.NoError(t, err)

		payload, err := GetPayloadFromActivity(&activity)
		require.Error(t, err)
		require.Nil(t, payload)
		require.Contains(t, err.Error(),
			"failed to parse previous anchors from activity: resource ID[urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA] not found in previous links") //nolint:lll
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

var testActivityWithCreate = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "previous": [{
        "id": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
        "url": "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
        "type": "Resource"
    }],
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            },
            {
                "href": "https://example.com/cas/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "alternate"
            }
        ],
        "resources": [
            "urn:multihash:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
            {
                "id": "urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
                "previousAnchor": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
                "type": "AnchorResource"
            }
        ]
    }]
}
`

var testAdditionalSample = `
{
   "type":"AnchorEvent",
   "attributedTo":"ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
   "published":"2021-01-27T09:30:00Z",
   "previous":[
      {
         "id":"urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
         "url":"ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
         "type":"Link"
      },
      {
         "id":"urn:multihash:uEiBTwjTl6EcrasUcGuHKs_4G-tBTvrjr_Yl3sBBlW_3Twwo",
         "url":"ipfs://bafkreictyi2ol2chfnvmkha24hflh7qg7lifhpvy5p6ys55qcbsvx7otym",
         "type":"Link"
      }
   ],
   "attachment":[
      {
         "type":"AnchorIndex",
         "generator":"https://example.com/spec#v1",
         "url":[
            {
               "href":"ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
               "type":"Link",
               "rel":"self"
            },
            {
               "href":"https://example.com/cas/bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
               "type":"Link",
               "rel":"alternate"
            }
         ],
         "resources":[
            "urn:multihash:uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
            {
               "id":"urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
               "previousAnchor":"urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
               "type":"AnchorResource"
            },
            {
               "id":"urn:multihash:uEiARIc_M1ZE_CmP-xApv_UTqZPncE1xmY0ugAdELz0MCogo",
               "previousAnchor":"urn:multihash:uEiBTwjTl6EcrasUcGuHKs_4G-tBTvrjr_Yl3sBBlW_3Twwo",
               "type":"AnchorResource"
            }
         ]
      }
   ]
}
`

var invalidActivityIntTypeForResource = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
         "resources":[
            123
         ]
    }]
}
`

var invalidActivityNoURN = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            "uEiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A"
        ]
    }]
}
`

var invalidActivityNoResourceInPrevious = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            {
               "id":"urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
               "previousAnchor":"urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
               "type":"AnchorResource"
            }
        ]
    }]
}
`

var invalidActivityIDInResourceNotAString = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "previous": [{
        "id": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
        "url": "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
        "type": "Resource"
    }],
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            {
                "id": 1234,
                "previousAnchor": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
                "type": "AnchorResource"
            }
        ]
    }]
}
`

var invalidActivityNoIDInResource = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "previous": [{
        "id": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
        "url": "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
        "type": "Resource"
    }],
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            {
                "previousAnchor": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
                "type": "AnchorResource"
            }
        ]
    }]
}
`

var invalidActivityNoPreviousAnchorInResource = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "previous": [{
        "id": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
        "url": "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
        "type": "Resource"
    }],
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            {
                "id": "urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
                "type": "AnchorResource"
            }
        ]
    }]
}
`

var invalidActivityNoTypeInResource = `
{
    "type": "AnchorEvent",
    "attributedTo": "ipns://k51qzi5uqu5dl3ua2aal8vdw82j4i8s112p495j1spfkd2blqygghwccsw1z0p",
    "published": "2021-01-27T09:30:00Z",
    "previous": [{
        "id": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF",
        "url": "ipfs://bafkreicdkwsgwgotjdoc6v6ai34o6y6ukohlxe3aadz4t3uvjitumdoymu",
        "type": "Resource"
    }],
    "attachment": [{
        "type": "AnchorIndex",
        "generator": "https://w3id.org/orb#v1",
        "url": [
            {
                "href": "ipfs://bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy",
                "type": "Link",
                "rel": "self"
            }
        ],
        "resources": [
            {
                "id": "urn:multihash:uEiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA",
                "previousAnchor": "urn:multihash:u2ouBBsyLDedeYciUmaihjWUmWhA3LVkruPZwSk7EeHWWqUZF"
            }
        ]
    }]
}
`
