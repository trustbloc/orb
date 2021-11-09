/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acceptlist

import (
	"errors"
	"net/url"
	"testing"

	storagemocks "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	acceptListTypeFollow        = "follow"
	acceptListTypeInviteWitness = "invite-witness"
)

var (
	domain1 = testutil.MustParseURL("https://domain1.com/services/orb")
	domain2 = testutil.MustParseURL("https://domain2.com/services/orb")
	domain3 = testutil.MustParseURL("https://domain3.com/services/orb")
	domain4 = testutil.MustParseURL("https://domain4.com/services/orb")
)

func TestManagerUpdateDelete(t *testing.T) {
	s := &storagemocks.MockStore{
		Store: make(map[string]storagemocks.DBEntry),
	}

	mgr := NewManager(s)
	require.NotNil(t, mgr)

	require.NoError(t, mgr.Update(acceptListTypeFollow,
		[]*url.URL{
			domain1,
			domain1, // Duplicates should be ignored.
			domain2,
		},
		nil,
	))

	require.NoError(t, mgr.Update(acceptListTypeInviteWitness,
		[]*url.URL{
			domain1,
			domain3,
		},
		nil,
	))

	acceptLists, err := mgr.GetAll()
	require.NoError(t, err)
	require.Len(t, acceptLists, 2)

	acceptList, err := mgr.Get(acceptListTypeFollow)
	require.NoError(t, err)

	require.Len(t, acceptList, 2)
	require.Contains(t, acceptList, domain1)
	require.Contains(t, acceptList, domain2)

	require.NoError(t, mgr.Update(acceptListTypeFollow,
		[]*url.URL{domain3, domain4},
		[]*url.URL{domain1},
	))

	acceptList, err = mgr.Get(acceptListTypeFollow)
	require.NoError(t, err)

	require.Len(t, acceptList, 3)
	require.Contains(t, acceptList, domain2)
	require.Contains(t, acceptList, domain3)
	require.Contains(t, acceptList, domain4)

	// No new URIs added. Request should be ignored.
	require.NoError(t, mgr.Update(acceptListTypeFollow,
		[]*url.URL{domain3, domain4},
		nil,
	))
}

func TestManagerError(t *testing.T) {
	t.Run("No type for Get", func(t *testing.T) {
		s := &storagemocks.MockStore{
			Store: make(map[string]storagemocks.DBEntry),
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get("")
		require.EqualError(t, err, "type is required")
	})

	t.Run("Query error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		s := &storagemocks.MockStore{
			Store:    make(map[string]storagemocks.DBEntry),
			ErrQuery: errExpected,
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get(acceptListTypeFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Iterator.Next error", func(t *testing.T) {
		errExpected := errors.New("injected iterator Next error")

		s := &storagemocks.MockStore{
			Store:   make(map[string]storagemocks.DBEntry),
			ErrNext: errExpected,
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get(acceptListTypeFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Iterator.Value error", func(t *testing.T) {
		errExpected := errors.New("injected iterator Value error")

		s := &storagemocks.MockStore{
			Store: map[string]storagemocks.DBEntry{
				"key": {
					Value: []byte("value"),
					Tags: []storage.Tag{
						{
							Name: newTag(""),
						},
						{
							Name: newTag(acceptListTypeFollow),
						},
					},
				},
			},
			ErrValue: errExpected,
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get(acceptListTypeFollow)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Unmarshal error -> ignore", func(t *testing.T) {
		s := &storagemocks.MockStore{
			Store: map[string]storagemocks.DBEntry{
				"key": {
					Value: []byte("invalid JSON string"),
					Tags: []storage.Tag{
						{
							Name: acceptListTypeFollow,
						},
					},
				},
			},
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get(acceptListTypeFollow)
		require.NoError(t, err, "unmarshal errors should be ignored")
	})

	t.Run("Parse URI error -> ignore", func(t *testing.T) {
		s := &storagemocks.MockStore{
			Store: map[string]storagemocks.DBEntry{
				"key": {
					Value: []byte(`":invalid URL"`),
					Tags: []storage.Tag{
						{
							Name: acceptListTypeFollow,
						},
					},
				},
			},
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		_, err := mgr.Get(acceptListTypeFollow)
		require.NoError(t, err, "parse URL errors should be ignored")
	})

	t.Run("Batch error", func(t *testing.T) {
		errExpected := errors.New("injected batch error")

		s := &storagemocks.MockStore{
			Store:    make(map[string]storagemocks.DBEntry),
			ErrBatch: errExpected,
		}

		mgr := NewManager(s)
		require.NotNil(t, mgr)

		err := mgr.Update(acceptListTypeFollow, []*url.URL{domain1}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}
