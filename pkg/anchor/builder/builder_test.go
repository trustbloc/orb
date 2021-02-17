/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package builder

import (
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/txn"
)

func TestSigner_New(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		builderParams := Params{
			Issuer: "issuer",
		}

		b, err := New(&mockSigner{}, builderParams)
		require.NoError(t, err)
		require.NotNil(t, b)
	})

	t.Run("error - missing issuer", func(t *testing.T) {
		s, err := New(&mockSigner{}, Params{})
		require.Error(t, err)
		require.Nil(t, s)
		require.Contains(t, err.Error(), "failed to verify builder parameters: missing issuer")
	})
}

func TestBuilder_Build(t *testing.T) {
	builderParams := Params{
		Issuer: "issuer",
	}

	t.Run("success", func(t *testing.T) {
		b, err := New(&mockSigner{}, builderParams)
		require.NoError(t, err)

		vc, err := b.Build(&txn.Payload{})
		require.NoError(t, err)
		require.NotEmpty(t, vc)
	})

	t.Run("error - error from signer", func(t *testing.T) {
		b, err := New(&mockSigner{Err: errors.New("signer error")},
			builderParams)
		require.NoError(t, err)

		vc, err := b.Build(&txn.Payload{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign credential: signer error")
		require.Nil(t, vc)
	})
}

func TestSigner_verifyBuilderParams(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		builderParams := Params{
			Issuer: "issuer",
		}

		err := verifyBuilderParams(builderParams)
		require.NoError(t, err)
	})

	t.Run("error - missing issuer", func(t *testing.T) {
		err := verifyBuilderParams(Params{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing issuer")
	})
}

type mockSigner struct {
	Err error
}

func (m *mockSigner) Sign(vc *verifiable.Credential) (*verifiable.Credential, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return vc, nil
}
