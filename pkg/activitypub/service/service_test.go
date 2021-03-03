/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/wmlogger"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestNewService(t *testing.T) {
	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ListenAddress: ":8311",
		PubSubFactory: func(serviceName string) PubSub {
			return mocks.NewPubSub()
		},
	}

	store1 := memstore.New(cfg1.ServiceName)
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1, service.WithUndeliverableHandler(undeliverableHandler1))
	require.NoError(t, err)

	service1.Start()

	require.Equal(t, service.StateStarted, service1.State())

	service1.Stop()

	require.Equal(t, service.StateStopped, service1.State())
}

func TestService(t *testing.T) {
	log.SetLevel(wmlogger.Module, log.WARNING)

	service1IRI := mustParseURL("http://localhost:8301/services/service1")
	service2IRI := mustParseURL("http://localhost:8302/services/service2")

	cfg1 := &Config{
		ServiceName:   "/services/service1",
		ListenAddress: ":8301",
	}

	store1 := memstore.New(cfg1.ServiceName)
	undeliverableHandler1 := mocks.NewUndeliverableHandler()

	service1, err := NewService(cfg1, store1,
		service.WithUndeliverableHandler(undeliverableHandler1),
	)
	require.NoError(t, err)

	defer service1.Stop()

	cfg2 := &Config{
		ServiceName:   "/services/service2",
		ListenAddress: ":8302",
		RetryOpts: &redelivery.Config{
			MaxRetries:     5,
			InitialBackoff: 10 * time.Millisecond,
			MaxBackoff:     time.Second,
			BackoffFactor:  1.2,
			MaxMessages:    20,
		},
	}

	store2 := memstore.New(cfg2.ServiceName)
	anchorCredHandler2 := mocks.NewAnchorCredentialHandler()
	undeliverableHandler2 := mocks.NewUndeliverableHandler()

	service2, err := NewService(cfg2, store2,
		service.WithUndeliverableHandler(undeliverableHandler2),
		service.WithAnchorCredentialHandler(anchorCredHandler2),
	)
	require.NoError(t, err)

	defer service2.Stop()

	subscriber2 := mocks.NewSubscriber(service2.Subscribe())

	service1.Start()

	// delay the start of Service2 to test redelivery
	go func() {
		time.Sleep(50 * time.Millisecond)
		service2.Start()
	}()

	t.Run("Create", func(t *testing.T) {
		const cid = "bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6mbky2amuw3inxsi3y"

		targetProperty := vocab.NewObjectProperty(vocab.WithObject(
			vocab.NewObject(
				vocab.WithID(cid),
				vocab.WithType(vocab.TypeCAS),
			),
		))

		obj, err := vocab.NewObjectWithDocument(vocab.MustUnmarshalToDoc([]byte(anchorCredential1)))
		if err != nil {
			panic(err)
		}

		unavailableServiceIRI := mustParseURL("http://localhost:8304/services/service4")

		create := vocab.NewCreateActivity(newActivityID(service1IRI.String()),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithActor(service1IRI),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI, unavailableServiceIRI),
		)

		require.NoError(t, service1.Outbox().Post(create))

		time.Sleep(1500 * time.Millisecond)

		activity, err := store1.GetActivity(spi.Outbox, create.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, create.ID(), activity.ID())

		activity, err = store2.GetActivity(spi.Inbox, create.ID())
		require.NoError(t, err)
		require.NotNil(t, activity)
		require.Equal(t, create.ID(), activity.ID())
		require.NotEmpty(t, subscriber2.Activities())
		require.NotEmpty(t, anchorCredHandler2.AnchorCred(cid))

		ua := undeliverableHandler1.Activities()
		require.Len(t, ua, 1)
		require.Equal(t, unavailableServiceIRI.String(), ua[0].ToURL)
	})
}

func newActivityID(serviceName string) string {
	return fmt.Sprintf("%s/%s", serviceName, uuid.New())
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}

const anchorCredential1 = `{
  "@context": [
	"https://www.w3.org/2018/credentials/v1",
	"https://trustbloc.github.io/Context/orb-v1.json"
  ],
  "id": "http://sally.example.com/transactions/bafkreihwsn",
  "type": [
	"VerifiableCredential",
	"AnchorCredential"
  ],
  "issuer": "https://sally.example.com/services/orb",
  "issuanceDate": "2021-01-27T09:30:10Z",
  "credentialSubject": {
	"anchorString": "bafkreihwsn",
	"namespace": "did:orb",
	"version": "1",
	"previousTransactions": {
	  "EiA329wd6Aj36YRmp7NGkeB5ADnVt8ARdMZMPzfXsjwTJA": "bafkreibmrm",
	  "EiABk7KK58BVLHMataxgYZjTNbsHgtD8BtjF0tOWFV29rw": "bafkreibh3w"
	}
  },
  "proofChain": [{}]
}`
