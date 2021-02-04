/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcsigner

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	cryptomock "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
)

func TestCrypto_SignCredential(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		vcSigner := New(&mockkms.KeyManager{}, &cryptomock.Crypto{}, "did:abc:123#key1", JSONWebSignature2020)

		signedVC, err := vcSigner.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.NoError(t, err)
		require.Equal(t, 1, len(signedVC.Proofs))
	})

	t.Run("test error from creator", func(t *testing.T) {
		c := New(&mockkms.KeyManager{}, &cryptomock.Crypto{}, "key1", JSONWebSignature2020)

		signedVC, err := c.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid verification method format")
		require.Nil(t, signedVC)
	})

	t.Run("test error from sign credential", func(t *testing.T) {
		c := New(&mockkms.KeyManager{},
			&cryptomock.Crypto{SignErr: fmt.Errorf("failed to sign")},
			"did:abc:123#key1", JSONWebSignature2020)

		signedVC, err := c.Sign(&verifiable.Credential{ID: "http://example.edu/credentials/1872"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign vc")
		require.Nil(t, signedVC)
	})
}
