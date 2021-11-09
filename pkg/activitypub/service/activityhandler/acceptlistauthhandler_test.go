/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

//go:generate counterfeiter -o ../mocks/acceptlistmgr.gen.go --fake-name AcceptListMgr . acceptListMgr

func TestAcceptListAuthHandler_AuthorizeActor(t *testing.T) {
	service1 := vocab.MustParseURL("https://domain1.com/services/orb")

	t.Run("Unauthorized", func(t *testing.T) {
		mgr := &mocks.AcceptListMgr{}

		h := NewAcceptListAuthHandler(FollowType, mgr)
		require.NotNil(t, h)

		actor := vocab.NewService(service1)

		ok, err := h.AuthorizeActor(actor)
		require.NoError(t, err)
		require.False(t, ok)
	})

	t.Run("Authorized", func(t *testing.T) {
		mgr := &mocks.AcceptListMgr{}

		mgr.GetReturns([]*url.URL{service1}, nil)

		h := NewAcceptListAuthHandler(FollowType, mgr)
		require.NotNil(t, h)

		actor := vocab.NewService(service1)

		ok, err := h.AuthorizeActor(actor)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("Error", func(t *testing.T) {
		mgr := &mocks.AcceptListMgr{}

		errExpected := errors.New("injected accept list manager error")
		mgr.GetReturns(nil, errExpected)

		h := NewAcceptListAuthHandler(FollowType, mgr)
		require.NotNil(t, h)

		actor := vocab.NewService(service1)

		ok, err := h.AuthorizeActor(actor)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.False(t, ok)
	})
}
