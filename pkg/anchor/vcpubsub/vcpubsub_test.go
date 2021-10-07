/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcpubsub

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
)

var anchorsURL = testutil.MustParseURL("hl:uEiBL1RVIr2DdyRE5h6b8bPys-PuVs5mMPPC778OtklPa-w")

func TestNewSubscriber(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		s, err := NewSubscriber(&mocks.PubSub{}, nil)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("Error", func(t *testing.T) {
		errExpected := errors.New("injected subscribe error")

		ps := &mocks.PubSub{}
		ps.SubscribeReturns(nil, errExpected)

		s, err := NewSubscriber(ps, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, s)
	})
}

func TestPubSub(t *testing.T) {
	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	p := NewPublisher(ps)
	require.NotNil(t, p)

	var mutex sync.RWMutex

	var gotAnchorEvents []*vocab.AnchorEventType

	s, err := NewSubscriber(ps,
		func(vc *vocab.AnchorEventType) error {
			mutex.Lock()
			gotAnchorEvents = append(gotAnchorEvents, vc)
			mutex.Unlock()

			return nil
		},
	)
	require.NoError(t, err)
	require.NotNil(t, s)

	s.Start()

	ae := vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL))

	require.NoError(t, p.Publish(ae))

	time.Sleep(100 * time.Millisecond)

	mutex.RLock()
	require.Len(t, gotAnchorEvents, 1)
	require.Equal(t, ae.Anchors().String(), gotAnchorEvents[0].Anchors().String())
	mutex.RUnlock()
}

func TestPublisherError(t *testing.T) {
	ae := vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL))

	t.Run("Marshal error", func(t *testing.T) {
		p := NewPublisher(&mocks.PubSub{})
		require.NotNil(t, p)

		errExpected := errors.New("injected marshal error")

		p.jsonMarshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err := p.Publish(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Publish error", func(t *testing.T) {
		errExpected := errors.New("injected publish error")

		ps := &mocks.PubSub{}
		ps.PublishReturns(errExpected)

		p := NewPublisher(ps)
		require.NotNil(t, p)

		err := p.Publish(ae)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.True(t, orberrors.IsTransient(err))
	})
}

func TestSubscriberError(t *testing.T) {
	ae := vocab.NewAnchorEvent(vocab.WithAnchors(anchorsURL))

	ps := mempubsub.New(mempubsub.Config{})
	defer ps.Stop()

	p := NewPublisher(ps)
	require.NotNil(t, p)

	t.Run("Invalid anchor event", func(t *testing.T) {
		var mutex sync.RWMutex

		var gotAnchorEvents []*vocab.AnchorEventType

		s, err := NewSubscriber(ps,
			func(vc *vocab.AnchorEventType) error {
				mutex.Lock()
				gotAnchorEvents = append(gotAnchorEvents, vc)
				mutex.Unlock()

				return nil
			},
		)
		require.NoError(t, err)
		require.NotNil(t, s)

		s.jsonUnmarshal = func(data []byte, v interface{}) error {
			return errors.New("injected unmarshal error")
		}

		s.Start()

		require.NoError(t, p.Publish(ae))

		time.Sleep(100 * time.Millisecond)

		mutex.RLock()
		require.Empty(t, gotAnchorEvents)
		mutex.RUnlock()
	})

	t.Run("Process error", func(t *testing.T) {
		t.Run("Transient error", func(t *testing.T) {
			var mutex sync.RWMutex

			var gotAnchorEvents []*vocab.AnchorEventType

			s, err := NewSubscriber(ps,
				func(vc *vocab.AnchorEventType) error {
					mutex.Lock()
					gotAnchorEvents = append(gotAnchorEvents, vc)
					mutex.Unlock()

					return orberrors.NewTransient(errors.New("injected transient error"))
				},
			)
			require.NoError(t, err)
			require.NotNil(t, s)

			s.Start()

			require.NoError(t, p.Publish(ae))

			time.Sleep(100 * time.Millisecond)

			mutex.RLock()
			require.Len(t, gotAnchorEvents, 1)
			mutex.RUnlock()
		})

		t.Run("Persistent error", func(t *testing.T) {
			var mutex sync.RWMutex

			var gotAnchorEvents []*vocab.AnchorEventType

			s, err := NewSubscriber(ps,
				func(vc *vocab.AnchorEventType) error {
					mutex.Lock()
					gotAnchorEvents = append(gotAnchorEvents, vc)
					mutex.Unlock()

					return errors.New("injected persistent error")
				},
			)
			require.NoError(t, err)
			require.NotNil(t, s)

			s.Start()

			require.NoError(t, p.Publish(ae))

			time.Sleep(100 * time.Millisecond)

			mutex.RLock()
			require.Len(t, gotAnchorEvents, 1)
			mutex.RUnlock()
		})
	})
}
