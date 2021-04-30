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

	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const defVCContext = "https://www.w3.org/2018/credentials/v1"

func TestGetTransactionPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		anchorSubject := &subject.Payload{
			OperationCount: 1,
			CoreIndex:      "coreIndex",
			Namespace:      "namespace",
			Version:        1,
		}

		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: anchorSubject,
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		parsedVC, err := verifiable.ParseCredential(vcBytes, verifiable.WithJSONLDDocumentLoader(testutil.GetLoader(t)))
		require.NoError(t, err)

		anchorSubjectFromVC, err := GetAnchorSubject(parsedVC)
		require.NoError(t, err)
		require.NotNil(t, anchorSubjectFromVC)

		require.Equal(t, anchorSubject.Namespace, anchorSubjectFromVC.Namespace)
		require.Equal(t, anchorSubject.OperationCount, anchorSubjectFromVC.OperationCount)
		require.Equal(t, anchorSubject.CoreIndex, anchorSubjectFromVC.CoreIndex)
		require.Equal(t, anchorSubject.Version, anchorSubjectFromVC.Version)
		require.Equal(t, anchorSubject.PreviousAnchors, anchorSubjectFromVC.PreviousAnchors)
	})

	t.Run("error - no credential subject", func(t *testing.T) {
		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: nil,
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		}

		anchorSubject, err := GetAnchorSubject(vc)
		require.Error(t, err)
		require.Nil(t, anchorSubject)
		require.Contains(t, err.Error(), "missing credential subject")
	})

	t.Run("error - unexpected interface for credential subject", func(t *testing.T) {
		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: verifiable.Subject{},
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		}

		anchorSubject, err := GetAnchorSubject(vc)
		require.Error(t, err)
		require.Nil(t, anchorSubject)
		require.Contains(t, err.Error(), "unexpected interface for credential subject")
	})
}
