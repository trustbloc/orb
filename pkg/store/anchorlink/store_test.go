/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorlink

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	mockstore "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/linkset"
)

var anchorIndexURL = testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockstore.Provider{
			ErrOpenStore: fmt.Errorf("failed to open store"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestStore_Put(t *testing.T) {
	t.Run("test save anchor event - success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.NoError(t, err)
	})

	t.Run("test save vc - error from store put", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrPut: fmt.Errorf("error put"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})
}

func TestStore_Get(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.NoError(t, err)

		al, err := s.Get(anchorIndexURL.String())
		require.NoError(t, err)
		require.Equal(t, al.Anchor().String(), anchorIndexURL.String())
	})

	t.Run("test success - with proof", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.NoError(t, err)

		ae, err := s.Get(anchorIndexURL.String())
		require.NoError(t, err)
		require.Equal(t, ae.Anchor().String(), anchorIndexURL.String())
	})

	t.Run("error - nil anchors URL", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Put(&linkset.Link{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to save anchor link: Anchor is empty")
	})

	t.Run("test error from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: fmt.Errorf("error get"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		vc, err := s.Get("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("ErrDataNotFound from store get", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrGet: storage.ErrDataNotFound,
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		vc, err := s.Get("vc1")
		require.True(t, errors.Is(err, orberrors.ErrContentNotFound))
		require.Nil(t, vc)
	})

	t.Run("test marshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		errExpected := errors.New("injected marshal error")

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("test unmarshal error", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.NoError(t, err)

		ae, err := s.Get(anchorIndexURL.String())
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, ae)
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(mem.NewProvider())
		require.NoError(t, err)

		err = s.Put(linkset.NewLink(anchorIndexURL, nil, nil, nil, nil, nil))
		require.NoError(t, err)

		ae, err := s.Get(anchorIndexURL.String())
		require.NoError(t, err)
		require.Equal(t, ae.Anchor().String(), anchorIndexURL.String())

		err = s.Delete(anchorIndexURL.String())
		require.NoError(t, err)
		require.Equal(t, ae.Anchor().String(), anchorIndexURL.String())
	})

	t.Run("test error from store delete", func(t *testing.T) {
		storeProvider := &mockstore.Provider{OpenStoreReturn: &mockstore.Store{
			ErrDelete: fmt.Errorf("error delete"),
		}}

		s, err := New(storeProvider)
		require.NoError(t, err)

		err = s.Delete("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error delete")
	})
}
