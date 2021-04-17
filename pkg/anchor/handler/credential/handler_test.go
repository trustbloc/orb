/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	var anchorCh chan []string

	c := New(anchorCh)
	require.NotNil(t, c)
}

func TestAnchorCredentialHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		anchorCh := make(chan []string, 100)

		c := New(anchorCh)

		id, err := url.Parse("https://orb.domain1.com/cas/bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy")
		require.NoError(t, err)

		cid := "bafkrwihwsnuregfeqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhoy"

		err = c.HandleAnchorCredential(id, cid, nil)
		require.NoError(t, err)
	})
}
