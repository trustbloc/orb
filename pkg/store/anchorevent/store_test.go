/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorevent

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

var anchorsURL = testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{
			ErrOpenStore: fmt.Errorf("failed to open store"),
		}, testutil.GetLoader(t))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("test save anchor event - success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.NoError(t, err)
	})

	t.Run("test save vc - error from store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrPut: fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider, testutil.GetLoader(t))
		require.NoError(t, err)

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.NoError(t, err)

		ae, err := s.Get(anchorsURL.String())
		require.NoError(t, err)
		require.Equal(t, ae.Anchors().String(), anchorsURL.String())
	})

	t.Run("test success - with proof", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.NoError(t, err)

		ae, err := s.Get(anchorsURL.String())
		require.NoError(t, err)
		require.Equal(t, ae.Anchors().String(), anchorsURL.String())
	})

	t.Run("error - nil anchors URL", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		err = s.Put(vocab.NewAnchorEvent())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save anchor event: Anchors is empty")
	})

	t.Run("test error from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider, testutil.GetLoader(t))
		require.NoError(t, err)

		vc, err := s.Get("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("test marshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("test unmarshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider(), testutil.GetLoader(t))
		require.NoError(t, err)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		err = s.Put(vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL)))
		require.NoError(t, err)

		ae, err := s.Get(anchorsURL.String())
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, ae)
	})
}
