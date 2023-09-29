/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operationparser

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/encoder"
)

func TestParser_ParseDID(t *testing.T) {
	t.Run("success - short form did", func(t *testing.T) {
		p := New(&MockOperationParser{})

		did, req, err := p.ParseDID("did:orb", "did:orb:abc")
		require.NoError(t, err)
		require.Nil(t, req)
		require.Equal(t, "did:orb:abc", did)
	})

	t.Run("success - short form did with cid", func(t *testing.T) {
		p := New(&MockOperationParser{})

		did, req, err := p.ParseDID("did:orb", "did:orb:cid:abc")
		require.NoError(t, err)
		require.Nil(t, req)
		require.Equal(t, "did:orb:cid:abc", did)
	})

	t.Run("success - long form did", func(t *testing.T) {
		p := New(&MockOperationParser{})

		encodedJSON := encoder.EncodeToString([]byte("{}"))

		did, req, err := p.ParseDID("did:orb", "did:orb:abc:"+encodedJSON)
		require.NoError(t, err)
		require.NotNil(t, req)
		require.Equal(t, "did:orb:abc", did)
	})
}

func TestParser_Parse(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := New(&MockOperationParser{})

		op, err := p.Parse("did:orb", []byte("{}"))
		require.NoError(t, err)
		require.NotNil(t, op)
	})
}

func TestParser_GetCommitment(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := New(&MockOperationParser{})

		c, err := p.GetCommitment([]byte("{}"))
		require.NoError(t, err)
		require.NotEmpty(t, c)
	})
}

func TestParser_GetRevealValue(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := New(&MockOperationParser{})

		rv, err := p.GetRevealValue([]byte("{}"))
		require.NoError(t, err)
		require.NotEmpty(t, rv)
	})
}

type MockOperationParser struct{}

// Parse mocks operation parsing.
func (m *MockOperationParser) Parse(_ string, _ []byte) (*operation.Operation, error) {
	return &operation.Operation{}, nil
}

// ParseDID mocks parsing did.
func (m *MockOperationParser) ParseDID(_, _ string) (string, []byte, error) {
	return "did:orb:abc", []byte("{}"), nil
}

// GetRevealValue mocks getting operation reveal value.
func (m *MockOperationParser) GetRevealValue(_ []byte) (string, error) {
	return "reveal", nil
}

// GetCommitment mocks getting operation commitment.
func (m *MockOperationParser) GetCommitment(_ []byte) (string, error) {
	return "commitment", nil
}
