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

	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
)

const defVCContext = "https://www.w3.org/2018/credentials/v1"

func TestVerifiableCredentialFromAnchorEvent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		previousAnchors := []*subject.SuffixAnchor{
			{Suffix: "suffix"},
		}

		payload := &subject.Payload{
			OperationCount:  1,
			CoreIndex:       "hl:uEiBqkaTRFZScQsXTw8IDBSpVxiKGqjJCDUcgiwpcd2frLw",
			Namespace:       "did:orb",
			Version:         0,
			PreviousAnchors: previousAnchors,
		}

		al, vcBytes, err := anchorlinkset.NewBuilder(
			generator.NewRegistry()).BuildAnchorLink(payload, datauri.MediaTypeDataURIGzipBase64,
			func(anchorHashlink, coreIndexHashlink string) (*verifiable.Credential, error) {
				return &verifiable.Credential{
					Types:   []string{"VerifiableCredential"},
					Context: []string{defVCContext},
					Subject: &builder.CredentialSubject{ID: anchorHashlink},
					Issuer: verifiable.Issuer{
						ID: "http://peer1.com",
					},
					Issued: &util.TimeWrapper{Time: time.Now()},
				}, nil
			},
		)
		require.NoError(t, err)

		vc2, err := VerifiableCredentialFromAnchorLink(al, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		vc2Bytes, err := vc2.MarshalJSON()
		require.NoError(t, err)

		require.Equal(t, vcBytes, vc2Bytes)
	})

	t.Run("Invalid anchor", func(t *testing.T) {
		al := &linkset.Link{}

		vc, err := VerifiableCredentialFromAnchorLink(al, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid anchor")
		require.Nil(t, vc)
	})

	t.Run("no replies", func(t *testing.T) {
		al := linkset.NewLink(
			testutil.MustParseURL("hl:sddsdsw"),
			testutil.MustParseURL("https://serice.domain1.com"),
			testutil.MustParseURL("https://profile.domain1.com"),
			nil, nil, nil)
		_, err := VerifiableCredentialFromAnchorLink(al, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.EqualError(t, err, "no replies in anchor link")
	})

	t.Run("invalid 'replies' data URI error", func(t *testing.T) {
		al := linkset.NewLink(
			testutil.MustParseURL("hl:sddsdsw"),
			testutil.MustParseURL("https://serice.domain1.com"),
			testutil.MustParseURL("https://profile.domain1.com"),
			nil, nil,
			linkset.NewReference(testutil.MustParseURL("https://somecontent"), linkset.TypeLinkset),
		)
		_, err := VerifiableCredentialFromAnchorLink(al, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported protocol")
	})

	t.Run("unmarshal VC from 'replies' error", func(t *testing.T) {
		replyDataURI, err := datauri.New([]byte("invalid"), datauri.MediaTypeDataURIJSON)
		require.NoError(t, err)

		al := linkset.NewLink(
			testutil.MustParseURL("hl:sddsdsw"),
			testutil.MustParseURL("https://serice.domain1.com"),
			testutil.MustParseURL("https://profile.domain1.com"),
			nil, nil,
			linkset.NewReference(replyDataURI, linkset.TypeLinkset),
		)
		_, err = VerifiableCredentialFromAnchorLink(al, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "embedded proof is not JSON")
	})
}
