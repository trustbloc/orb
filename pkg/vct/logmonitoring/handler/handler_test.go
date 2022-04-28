/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

const (
	actorURL = "https://domain.com/orb/services"
	logURL   = "https://vct.com/log"
)

func TestNew(t *testing.T) {
	c := New(nil, nil)
	require.NotNil(t, c)
}

func TestLogMonitorHandler_Accept(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		testURL, err := url.Parse(logURL)
		require.NoError(t, err)

		c := New(store, &mockLogResolver{URL: testURL})
		require.NotNil(t, c)

		actor, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Accept(actor)
		require.NoError(t, err)
	})

	t.Run("success - log not found", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		c := New(store, &mockLogResolver{Err: orberrors.ErrContentNotFound})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Accept(source)
		require.NoError(t, err)
	})

	t.Run("error - log resolution error", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		c := New(store, &mockLogResolver{Err: fmt.Errorf("log resolution error")})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Accept(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "log resolution error")
	})

	t.Run("error - store error", func(t *testing.T) {
		testURL, err := url.Parse(logURL)
		require.NoError(t, err)

		c := New(&mockStore{ActivateErr: fmt.Errorf("store error")}, &mockLogResolver{URL: testURL})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Accept(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
	})
}

func TestLogMonitorHandler_Undo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		testURL, err := url.Parse(logURL)
		require.NoError(t, err)

		c := New(store, &mockLogResolver{URL: testURL})
		require.NotNil(t, c)

		actor, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Accept(actor)
		require.NoError(t, err)

		err = c.Undo(actor)
		require.NoError(t, err)
	})

	t.Run("success - log not found", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		c := New(store, &mockLogResolver{Err: orberrors.ErrContentNotFound})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Undo(source)
		require.NoError(t, err)
	})

	t.Run("error - log resolution error", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		c := New(store, &mockLogResolver{Err: fmt.Errorf("log resolution error")})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Undo(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "log resolution error")
	})

	t.Run("error - store error", func(t *testing.T) {
		testURL, err := url.Parse(logURL)
		require.NoError(t, err)

		c := New(&mockStore{DeactivateErr: fmt.Errorf("store error")}, &mockLogResolver{URL: testURL})
		require.NotNil(t, c)

		source, err := url.Parse(actorURL)
		require.NoError(t, err)

		err = c.Undo(source)
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
	})
}

type mockLogResolver struct {
	URL *url.URL
	Err error
}

func (m *mockLogResolver) ResolveLog(_ string) (*url.URL, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.URL, nil
}

type mockStore struct {
	ActivateErr   error
	DeactivateErr error
}

func (m *mockStore) Activate(_ string) error {
	return m.ActivateErr
}

func (m *mockStore) Deactivate(_ string) error {
	return m.DeactivateErr
}
