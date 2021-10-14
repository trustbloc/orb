/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
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
		previousAnchors := make(map[string]string)
		previousAnchors["suffix"] = ""

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

		act, err := anchorevent.BuildAnchorEvent(payload, contentObj, vc)
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
}
