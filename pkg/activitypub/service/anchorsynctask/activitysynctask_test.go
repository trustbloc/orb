/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchorsynctask

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	mocks2 "github.com/trustbloc/orb/pkg/activitypub/store/mocks"
	spi2 "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/aptestutil"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/taskmgr.gen.go --fake-name TaskManager . taskManager

func TestRegister(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		require.NoError(t, Register(
			Config{},
			mocks.NewTaskManager("anchor-sync"), &mocks.ActivityPubClient{},
			memstore.New("service1"), storage.NewMockStoreProvider(),
			func() spi.InboxHandler {
				return nil
			},
		))
	})

	t.Run("Open store error", func(t *testing.T) {
		p := storage.NewMockStoreProvider()

		errExpected := errors.New("injected open store error")

		p.ErrOpenStoreHandle = errExpected

		err := Register(
			Config{},
			mocks.NewTaskManager("anchor-sync"), &mocks.ActivityPubClient{},
			memstore.New("service1"), p,
			func() spi.InboxHandler {
				return nil
			},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestRun(t *testing.T) {
	serviceIRI := testutil.MustParseURL("https://domain1.com/services/orb")
	service2IRI := testutil.MustParseURL("https://domain2.com/services/orb")

	pubKeyIRI := testutil.NewMockID(service2IRI, "/keys/main-key")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKeyPem, err := getPublicKeyPem(pubKey)
	require.NoError(t, err)

	publicKey := vocab.NewPublicKey(
		vocab.WithID(pubKeyIRI),
		vocab.WithOwner(service2IRI),
		vocab.WithPublicKeyPem(string(pubKeyPem)),
	)

	announceActivities := aptestutil.NewMockAnnounceActivities(3)
	createActivities := aptestutil.NewMockCreateActivities(3)

	activities := append(createActivities, announceActivities...) //nolint: gocritic
	activities = append(activities, aptestutil.NewMockLikeActivities(1)...)
	activities = append(activities, announceActivities[0]) // Add a duplicate activity.

	apStore := memstore.New("service1")

	require.NoError(t, apStore.AddReference(spi2.Following, serviceIRI, service2IRI))
	require.NoError(t, apStore.AddReference(spi2.Follower, serviceIRI, service2IRI))
	require.NoError(t, apStore.AddActivity(createActivities[0])) // This activity should be ignored.

	apClient := mocks.NewActivitPubClient().
		WithActor(
			aptestutil.NewMockService(service2IRI, aptestutil.WithPublicKey(publicKey)),
		).
		WithActivities(activities)

	t.Run("Success", func(t *testing.T) {
		handler := &mockHandler{}

		handler.duplicateAnchors = append(handler.duplicateAnchors, announceActivities[1], createActivities[1])

		task, err := newTask(
			serviceIRI, apClient, apStore, storage.NewMockStoreProvider(), time.Second,
			func() spi.InboxHandler {
				return handler
			},
		)
		require.NoError(t, err)
		require.NotNil(t, task)

		task.run()

		require.Emptyf(t, len(handler.activities),
			"Should not have processed any activities since the minimum activity age is one second")

		time.Sleep(time.Second)

		task.run()

		require.Equal(t, 3, len(handler.activities))
	})

	t.Run("QueryReferences error", func(t *testing.T) {
		errExpected := errors.New("injected query error")

		s := &mocks.ActivityStore{}
		s.QueryReferencesReturns(nil, errExpected)

		handler := &mockHandler{}

		task, err := newTask(
			serviceIRI, apClient, s, storage.NewMockStoreProvider(), time.Nanosecond,
			func() spi.InboxHandler {
				return handler
			},
		)
		require.NoError(t, err)
		require.NotNil(t, task)

		task.run()

		require.Empty(t, handler.activities)
	})

	t.Run("ReferenceIterator error", func(t *testing.T) {
		errExpected := errors.New("injected iterator error")

		it := &mocks2.ReferenceIterator{}
		it.NextReturns(nil, errExpected)

		s := &mocks.ActivityStore{}
		s.QueryReferencesReturns(it, nil)

		handler := &mockHandler{}

		task, err := newTask(
			serviceIRI, apClient, s, storage.NewMockStoreProvider(), time.Nanosecond,
			func() spi.InboxHandler {
				return handler
			},
		)
		require.NoError(t, err)
		require.NotNil(t, task)

		task.run()

		require.Empty(t, handler.activities)
	})

	t.Run("GetActor error", func(t *testing.T) {
		errExpected := errors.New("injected client error")

		apClient := mocks.NewActivitPubClient().WithError(errExpected)

		handler := &mockHandler{}

		task, err := newTask(
			serviceIRI, apClient, apStore, storage.NewMockStoreProvider(), time.Nanosecond,
			func() spi.InboxHandler {
				return handler
			},
		)
		require.NoError(t, err)
		require.NotNil(t, task)

		task.run()

		require.Empty(t, handler.activities)
	})
}

func getPublicKeyPem(pubKey interface{}) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   keyBytes,
	}), nil
}

type mockHandler struct {
	activities       []*vocab.ActivityType
	duplicateAnchors []*vocab.ActivityType
	err              error
}

func (m *mockHandler) HandleCreateActivity(ctx context.Context, source *url.URL, a *vocab.ActivityType, announce bool) error {
	if m.err != nil {
		return m.err
	}

	if m.exists(a) {
		return spi.ErrDuplicateAnchorEvent
	}

	m.activities = append(m.activities, a)

	return nil
}

func (m *mockHandler) HandleAnnounceActivity(ctx context.Context, src *url.URL, a *vocab.ActivityType) (int, error) {
	if m.err != nil {
		return 0, m.err
	}

	if m.exists(a) {
		return 0, spi.ErrDuplicateAnchorEvent
	}

	m.activities = append(m.activities, a)

	return 1, nil
}

func (m *mockHandler) exists(activity *vocab.ActivityType) bool {
	for _, a := range m.duplicateAnchors {
		if a.ID().String() == activity.ID().String() {
			return true
		}
	}

	return false
}
