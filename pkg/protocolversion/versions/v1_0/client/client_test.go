/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"

	"github.com/trustbloc/orb/pkg/protocolversion/mocks"
)

func TestFactory_Create(t *testing.T) {
	f := New()
	require.NotNil(t, f)

	casClient := &mocks.CasClient{}

	t.Run("success", func(t *testing.T) {
		pv, err := f.Create("1.0", casClient)
		require.NoError(t, err)
		require.NotNil(t, pv)
	})
}

func TestOperationProviderWrapper_GetTxnOperations(t *testing.T) {
	t.Run("parse anchor data failed", func(t *testing.T) {
		p := protocol.Protocol{}
		opWrapper := operationProviderWrapper{
			Protocol: &p, parser: operationparser.New(p),
			dp: compression.New(compression.WithDefaultAlgorithms()),
		}

		anchoredOperations, err := opWrapper.GetTxnOperations(&txn.SidetreeTxn{
			AnchorString:         "1.2.3",
			EquivalentReferences: []string{"webcas:orb.domain1.com"},
		})
		require.EqualError(t, err, "parse anchor data[1.2.3] failed: expecting [2] parts, got [3] parts")
		require.Nil(t, anchoredOperations)
	})
}

func TestCasClientWrapper_Read(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		casClient := &mocks.CasClient{}
		casClient.ReadReturns([]byte("hello world"), nil)

		wrapper := &casClientWrapper{
			casReader:                casClient,
			casHintWithTrailingColon: "webcas:orb.domain1.com:",
		}

		data, err := wrapper.Read("cid")
		require.NoError(t, err)
		require.NotNil(t, data)
	})
	t.Run("error - cas error", func(t *testing.T) {
		casClient := &mocks.CasClient{}
		casClient.ReadReturns(nil, fmt.Errorf("cas error"))

		wrapper := &casClientWrapper{
			casReader: casClient,
		}

		data, err := wrapper.Read("cid")
		require.Error(t, err)
		require.Nil(t, data)
		require.Contains(t, err.Error(), "cas error")
	})
}
