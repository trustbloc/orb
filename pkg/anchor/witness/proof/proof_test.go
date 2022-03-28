/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proof

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func Test(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		testURI, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		w := &Witness{Type: WitnessTypeBatch, URI: vocab.NewURLProperty(testURI), HasLog: true}
		require.Equal(t, w.String(), "{type:batch, witness:http://domain.com/service, log:true}")
	})

	t.Run("success", func(t *testing.T) {
		testURI, err := url.Parse("http://domain.com/service")
		require.NoError(t, err)

		wp := &WitnessProof{
			Witness: &Witness{
				Type:   WitnessTypeBatch,
				URI:    vocab.NewURLProperty(testURI),
				HasLog: true,
			},
			Proof: []byte("proof"),
		}
		require.Equal(t, wp.String(), "{type:batch, witness:http://domain.com/service, log:true, proof:proof}")
	})
}
