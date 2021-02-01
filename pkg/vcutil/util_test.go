/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcutil

import (
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/api/txn"
)

const defVCContext = "https://www.w3.org/2018/credentials/v1"

func TestGetTransactionPayload(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		txnInfo := &txn.Payload{
			AnchorString: "anchor",
			Namespace:    "namespace",
			Version:      1,
		}

		vc := &verifiable.Credential{
			Types:   []string{"VerifiableCredential"},
			Context: []string{defVCContext},
			Subject: txnInfo,
			Issuer: verifiable.Issuer{
				ID: "http://peer1.com",
			},
			Issued: &util.TimeWithTrailingZeroMsec{Time: time.Now()},
		}

		vcBytes, err := vc.MarshalJSON()
		require.NoError(t, err)

		parsedVC, err := verifiable.ParseCredential(vcBytes)
		require.NoError(t, err)

		txnInfoFromVC, err := GetTransactionPayload(parsedVC)
		require.NoError(t, err)
		require.NotNil(t, txnInfoFromVC)

		require.Equal(t, txnInfo.Namespace, txnInfoFromVC.Namespace)
		require.Equal(t, txnInfo.AnchorString, txnInfoFromVC.AnchorString)
		require.Equal(t, txnInfo.Version, txnInfoFromVC.Version)
		require.Equal(t, txnInfo.PreviousTransactions, txnInfoFromVC.PreviousTransactions)
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

		txnInfo, err := GetTransactionPayload(vc)
		require.Error(t, err)
		require.Nil(t, txnInfo)
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

		txnInfo, err := GetTransactionPayload(vc)
		require.Error(t, err)
		require.Nil(t, txnInfo)
		require.Contains(t, err.Error(), "unexpected interface for credential subject")
	})
}
