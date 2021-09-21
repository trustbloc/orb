/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linkstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s, err := New(storage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("Open store error", func(t *testing.T) {
		provider := storage.NewMockStoreProvider()

		errExpected := errors.New("injected open store error")

		provider.ErrOpenStoreHandle = errExpected

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})

	t.Run("Open store error", func(t *testing.T) {
		provider := storage.NewMockStoreProvider()

		errExpected := errors.New("injected set config error")

		provider.ErrSetStoreConfig = errExpected

		s, err := New(provider)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestStore_PutLinks(t *testing.T) {
	provider := storage.NewMockStoreProvider()

	s, err := New(provider)
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Success", func(t *testing.T) {
		const hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		const hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash1)
		link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodzZ4OVhtYkNTZjRfTWc", hash1)
		link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash2)

		require.NoError(t, s.PutLinks(
			[]*url.URL{
				testutil.MustParseURL(link1),
				testutil.MustParseURL(link2),
				testutil.MustParseURL(link3),
			},
		))
	})

	t.Run("Invalid hashlink", func(t *testing.T) {
		require.Error(t, s.PutLinks([]*url.URL{testutil.MustParseURL("https://xxx")}))
	})

	t.Run("Marshal error", func(t *testing.T) {
		s.marshal = func(i interface{}) ([]byte, error) { return nil, errors.New("injected marshal error") }
		defer func() { s.marshal = json.Marshal }()

		require.Error(t, s.PutLinks([]*url.URL{testutil.MustParseURL("hl:xxx")}))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		provider.Store.ErrBatch = errExpected

		err := s.PutLinks([]*url.URL{testutil.MustParseURL("hl:xxx")})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestStore_GetLinks(t *testing.T) {
	const (
		hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"
	)

	provider := storage.NewMockStoreProvider()

	s, err := New(provider)
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Success", func(t *testing.T) {
		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodUZzbk1ucmdEa3NBdFEtd0NhS3c", hash1)
		link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodWJRbWI2SzZ4OVhtYkNTZjRfTWc", hash1)
		link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodUZzbk1ucmdEa3NBdFEtd0NhS3c", hash2)

		require.NoError(t, s.PutLinks(
			[]*url.URL{
				testutil.MustParseURL(link1),
				testutil.MustParseURL(link2),
				testutil.MustParseURL(link3),
			},
		))

		links, err := s.GetLinks(hash1)
		require.NoError(t, err)
		require.Len(t, links, 2)

		links, err = s.GetLinks(hash2)
		require.NoError(t, err)
		require.Len(t, links, 1)
	})

	t.Run("Query error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		provider.Store.ErrQuery = errExpected
		defer func() { provider.Store.ErrQuery = nil }()

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Iterator.Next error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		provider.Store.ErrNext = errExpected
		defer func() { provider.Store.ErrNext = nil }()

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Iterator.Value error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		provider.Store.ErrValue = errExpected
		defer func() { provider.Store.ErrValue = nil }()

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodHRwczovL29yYi5kb0NhS3c", hash1)

		require.NoError(t, s.PutLinks([]*url.URL{testutil.MustParseURL(link1)}))

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		errExpected := errors.New("injected unmarshal error")

		s.unmarshal = func(data []byte, v interface{}) error { return errExpected }

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodHRwczovL29yYi5kb21hNhS3c", hash1)

		require.NoError(t, s.PutLinks([]*url.URL{testutil.MustParseURL(link1)}))

		links, err := s.GetLinks(hash1)
		require.Error(t, err)
		require.Len(t, links, 0)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, orberrors.IsTransient(err))
	})
}

func TestStore_DeleteLinks(t *testing.T) {
	provider := storage.NewMockStoreProvider()

	s, err := New(provider)
	require.NoError(t, err)
	require.NotNil(t, s)

	t.Run("Success", func(t *testing.T) {
		const hash1 = "uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ"
		const hash2 = "uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw"

		link1 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash1)
		link2 := fmt.Sprintf("hl:%s:uoQ-BeEtodzZ4OVhtYkNTZjRfTWc", hash1)
		link3 := fmt.Sprintf("hl:%s:uoQ-BeEtodmdEa3NBdFEtd0NhS3c", hash2)

		require.NoError(t, s.DeleteLinks(
			[]*url.URL{
				testutil.MustParseURL(link1),
				testutil.MustParseURL(link2),
				testutil.MustParseURL(link3),
			},
		))
	})

	t.Run("Invalid hashlink", func(t *testing.T) {
		require.Error(t, s.DeleteLinks([]*url.URL{testutil.MustParseURL("https://xxx")}))
	})

	t.Run("Marshal error", func(t *testing.T) {
		s.marshal = func(i interface{}) ([]byte, error) { return nil, errors.New("injected marshal error") }
		defer func() { s.marshal = json.Marshal }()

		require.Error(t, s.DeleteLinks([]*url.URL{testutil.MustParseURL("hl:xxx")}))
	})

	t.Run("Store error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		provider.Store.ErrBatch = errExpected

		err := s.DeleteLinks([]*url.URL{testutil.MustParseURL("hl:xxx")})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}
