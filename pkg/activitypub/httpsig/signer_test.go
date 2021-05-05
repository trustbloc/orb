/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httpsig

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	const keyID = "123456"

	t.Run("GET", func(t *testing.T) {
		s := NewSigner(DefaultGetSignerConfig(), &mockcrypto.Crypto{}, &mockkms.KeyManager{}, keyID)

		req, err := http.NewRequest(http.MethodGet, "https://domain1.com", nil)
		require.NoError(t, err)

		require.NoError(t, s.SignRequest("pubKeyID", req))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("POST", func(t *testing.T) {
		s := NewSigner(DefaultPostSignerConfig(), &mockcrypto.Crypto{}, &mockkms.KeyManager{}, keyID)

		payload := []byte("payload")

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		require.NoError(t, s.SignRequest("pubKeyID", req))

		require.NotEmpty(t, req.Header[dateHeader])
		require.NotEmpty(t, req.Header["Digest"])
		require.NotEmpty(t, req.Header["Signature"])
	})

	t.Run("Signer error", func(t *testing.T) {
		errExpected := errors.New("injected KMS error")

		s := NewSigner(SignerConfig{}, &mockcrypto.Crypto{}, &mockkms.KeyManager{GetKeyErr: errExpected}, keyID)

		payload := []byte("payload")

		req, err := http.NewRequest(http.MethodPost, "https://domain1.com", bytes.NewBuffer(payload))
		require.NoError(t, err)

		err = s.SignRequest("pubKeyID", req)
		require.Error(t, err)
		require.Contains(t, err.Error(), err.Error())
	})
}
