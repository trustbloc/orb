/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginsmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/store/mocks"
)

func TestNew(t *testing.T) {
	it := &mocks.Iterator{}
	it.NextReturns(false, nil)

	s := &mocks.Store{}
	s.QueryReturns(it, nil)

	t.Run("No initial origins -> Success", func(t *testing.T) {
		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)
	})

	t.Run("With initial origins -> Success", func(t *testing.T) {
		m, err := New(s,
			testutil.MustParseURL("https://orb.domain1.com"),
			testutil.MustParseURL("https://orb.domain2.com"),
		)
		require.NoError(t, err)
		require.NotNil(t, m)
	})

	t.Run("With initial origins -> store error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		s := &mocks.Store{}
		s.QueryReturns(nil, errExpected)

		m, err := New(s,
			testutil.MustParseURL("https://orb.domain1.com"),
			testutil.MustParseURL("https://orb.domain2.com"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, m)
	})
}

func TestManager_Update(t *testing.T) {
	it := &mocks.Iterator{}
	it.NextReturns(false, nil)

	t.Run("Success", func(t *testing.T) {
		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		require.NoError(t, m.Update(
			[]*url.URL{testutil.MustParseURL("https://orb.domain1.com")},
			[]*url.URL{testutil.MustParseURL("https://orb.domain2.com")}),
		)
	})

	t.Run("Batch store error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		s := &mocks.Store{}
		s.QueryReturns(it, nil)
		s.BatchReturns(errExpected)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		err = m.Update([]*url.URL{testutil.MustParseURL("https://orb.domain1.com")}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Update -> marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		m.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err = m.Update([]*url.URL{testutil.MustParseURL("https://orb.domain1.com")}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestManager_Get(t *testing.T) {
	uri1 := testutil.MustParseURL("https://orb.domain1.com")
	uri2 := testutil.MustParseURL("https://orb.domain2.com")

	t.Run("Success", func(t *testing.T) {
		value1Bytes, err := json.Marshal(config{AllowedOrigin: uri1.String()})
		require.NoError(t, err)

		value2Bytes, err := json.Marshal(config{AllowedOrigin: uri2.String()})
		require.NoError(t, err)

		it := &mocks.Iterator{}
		it.NextReturnsOnCall(0, true, nil)
		it.ValueReturnsOnCall(0, value1Bytes, nil)
		it.NextReturnsOnCall(1, true, nil)
		it.ValueReturnsOnCall(1, value2Bytes, nil)
		it.NextReturnsOnCall(2, false, nil)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.NoError(t, err)
		require.Len(t, origins, 2)
		require.True(t, contains(origins, uri1))
		require.True(t, contains(origins, uri2))
	})

	t.Run("Query error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		s := &mocks.Store{}
		s.QueryReturns(nil, errExpected)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, origins)
	})

	t.Run("Iterator.Next error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		it := &mocks.Iterator{}
		it.NextReturns(false, errExpected)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, origins)
	})

	t.Run("Iterator.Next(2) error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		value1Bytes, err := json.Marshal(config{AllowedOrigin: uri1.String()})
		require.NoError(t, err)

		it := &mocks.Iterator{}
		it.NextReturnsOnCall(0, true, nil)
		it.ValueReturnsOnCall(0, value1Bytes, nil)
		it.NextReturnsOnCall(1, false, errExpected)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, origins)
	})

	t.Run("Iterator.Value error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		it := &mocks.Iterator{}
		it.NextReturns(true, nil)
		it.ValueReturns(nil, errExpected)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, origins)
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		it := &mocks.Iterator{}
		it.NextReturns(true, nil)
		it.ValueReturns([]byte("}"), nil)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
		require.Nil(t, origins)
	})

	t.Run("Invalid URI error -> ignore", func(t *testing.T) {
		it := &mocks.Iterator{}
		it.NextReturnsOnCall(0, true, nil)
		it.NextReturnsOnCall(1, true, nil)
		it.NextReturnsOnCall(2, false, nil)
		it.ValueReturnsOnCall(0, []byte(`{"allowedOrigin":"%"}`), nil)
		it.ValueReturnsOnCall(1, []byte(fmt.Sprintf(`{"allowedOrigin":"%s"}`, uri1)), nil)

		s := &mocks.Store{}
		s.QueryReturns(it, nil)

		m, err := New(s)
		require.NoError(t, err)
		require.NotNil(t, m)

		origins, err := m.Get()
		require.NoError(t, err)
		require.Len(t, origins, 1)
		require.True(t, contains(origins, uri1))
	})
}
