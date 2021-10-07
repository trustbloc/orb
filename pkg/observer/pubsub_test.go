/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package observer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

//go:generate counterfeiter -o ../mocks/pubsub.gen.go --fake-name PubSub . pubSub

func TestPubSub(t *testing.T) {
	p := mempubsub.New(mempubsub.DefaultConfig())
	require.NotNil(t, p)

	var mutex sync.RWMutex

	var gotAnchors []*anchorinfo.AnchorInfo

	var gotDIDs []string

	ps, err := NewPubSub(p,
		func(anchor *anchorinfo.AnchorInfo) error {
			mutex.Lock()
			gotAnchors = append(gotAnchors, anchor)
			mutex.Unlock()

			return nil
		},
		func(did string) error {
			mutex.Lock()
			gotDIDs = append(gotDIDs, did)
			mutex.Unlock()

			return nil
		},
		5,
	)
	require.NoError(t, err)
	require.NotNil(t, ps)

	ps.Start()
	defer ps.Stop()

	anchorInfo := &anchorinfo.AnchorInfo{
		Hashlink: "abcdefg",
	}

	did := "123456"

	require.NoError(t, ps.PublishAnchor(anchorInfo))
	require.NoError(t, ps.PublishDID(did))

	time.Sleep(1 * time.Second)

	mutex.RLock()
	require.Len(t, gotAnchors, 1)
	require.Equal(t, anchorInfo, gotAnchors[0])
	require.Len(t, gotDIDs, 1)
	require.Equal(t, did, gotDIDs[0])
	mutex.RUnlock()
}

func TestPubSub_Error(t *testing.T) {
	t.Run("Subscribe anchor error", func(t *testing.T) {
		errExpected := errors.New("injected pub/sub error")

		p := &mocks.PubSub{}
		p.SubscribeWithOptsReturns(nil, errExpected)

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error { return nil },
			func(did string) error { return nil },
			5,
		)
		require.Error(t, err)
		require.Nil(t, ps)
	})

	t.Run("Subscribe DID error", func(t *testing.T) {
		errExpected := errors.New("injected pub/sub error")

		p := &mocks.PubSub{}
		p.SubscribeWithOptsReturnsOnCall(1, nil, errExpected)

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error { return nil },
			func(did string) error { return nil },
			5,
		)
		require.Error(t, err)
		require.Nil(t, ps)
	})

	t.Run("Marshal error", func(t *testing.T) {
		p := mempubsub.New(mempubsub.DefaultConfig())
		require.NotNil(t, p)

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error { return nil },
			func(did string) error { return nil },
			5,
		)
		require.NoError(t, err)
		require.NotNil(t, ps)

		errExpected := errors.New("injected marshal error")

		ps.jsonMarshal = func(v interface{}) ([]byte, error) { return nil, errExpected }

		ps.Start()
		defer ps.Stop()

		err = ps.PublishAnchor(&anchorinfo.AnchorInfo{Hashlink: "abcdefg"})
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())

		err = ps.PublishDID("123456")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Unmarshal error", func(t *testing.T) {
		p := mempubsub.New(mempubsub.DefaultConfig())
		require.NotNil(t, p)

		var mutex sync.RWMutex

		var gotAnchors []*anchorinfo.AnchorInfo

		var gotDIDs []string

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error {
				mutex.Lock()
				gotAnchors = append(gotAnchors, anchor)
				mutex.Unlock()

				return nil
			},
			func(did string) error {
				mutex.Lock()
				gotDIDs = append(gotDIDs, did)
				mutex.Unlock()

				return nil
			},
			5,
		)
		require.NoError(t, err)
		require.NotNil(t, ps)

		errExpected := errors.New("injected unmarshal error")

		ps.jsonUnmarshal = func(data []byte, v interface{}) error { return errExpected }

		ps.Start()
		defer ps.Stop()

		require.NoError(t, ps.PublishAnchor(&anchorinfo.AnchorInfo{Hashlink: "abcdefg"}))
		require.NoError(t, ps.PublishDID("123456"))

		time.Sleep(1 * time.Second)

		mutex.RLock()
		require.Empty(t, gotAnchors)
		require.Empty(t, gotDIDs)
		mutex.RUnlock()
	})

	t.Run("Transient error", func(t *testing.T) {
		p := mempubsub.New(mempubsub.DefaultConfig())
		require.NotNil(t, p)

		errExpected := errors.New("injected unmarshal error")

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error { return orberrors.NewTransient(errExpected) },
			func(did string) error { return orberrors.NewTransient(errExpected) },
			5,
		)
		require.NoError(t, err)
		require.NotNil(t, ps)

		ps.Start()
		defer ps.Stop()

		require.NoError(t, ps.PublishAnchor(&anchorinfo.AnchorInfo{Hashlink: "abcdefg"}))
		require.NoError(t, ps.PublishDID("123456"))
	})

	t.Run("Not started error", func(t *testing.T) {
		p := mempubsub.New(mempubsub.DefaultConfig())
		require.NotNil(t, p)

		ps, err := NewPubSub(p,
			func(anchor *anchorinfo.AnchorInfo) error { return nil },
			func(did string) error { return nil },
			5,
		)
		require.NoError(t, err)
		require.NotNil(t, ps)

		require.EqualError(t, ps.PublishAnchor(&anchorinfo.AnchorInfo{Hashlink: "abcdefg"}), lifecycle.ErrNotStarted.Error())
		require.EqualError(t, ps.PublishDID("123456"), lifecycle.ErrNotStarted.Error())
	})
}
