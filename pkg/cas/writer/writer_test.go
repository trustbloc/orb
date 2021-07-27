/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"

	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

func TestWrite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		casClient := mocks.NewMockCasClient(nil)

		cas := New(casClient, "webcas:domain.com", &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, hint, err := cas.Write([]byte("content"))
		require.Nil(t, err)
		require.NotEmpty(t, cid)
		require.Equal(t, hint, "webcas:domain.com")

		read, err := casClient.Read(cid)
		require.Nil(t, err)
		require.NotNil(t, read)
	})

	t.Run("success - no hint provided", func(t *testing.T) {
		casClient := mocks.NewMockCasClient(nil)

		cas := New(casClient, "", &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, hint, err := cas.Write([]byte("content"))
		require.Nil(t, err)
		require.NotEmpty(t, cid)
		require.Empty(t, hint)

		read, err := casClient.Read(cid)
		require.Nil(t, err)
		require.NotNil(t, read)
	})

	t.Run("error - core cas error", func(t *testing.T) {
		casClient := mocks.NewMockCasClient(fmt.Errorf("cas write error"))

		cas := New(casClient, "webcas:domain.com", &orbmocks.MetricsProvider{})
		require.NotNil(t, cas)

		cid, hint, err := cas.Write([]byte("content"))
		require.Error(t, err)
		require.Empty(t, cid)
		require.Empty(t, hint)
		require.Contains(t, err.Error(), "failed to write to core cas: cas write error")
	})
}
