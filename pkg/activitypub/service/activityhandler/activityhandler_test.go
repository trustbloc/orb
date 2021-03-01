/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestNew(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
		BufferSize:  100,
	}

	h := New(cfg, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
	require.NotNil(t, h)

	require.Equal(t, spi.StateNotStarted, h.State())

	h.Start()

	require.Equal(t, spi.StateStarted, h.State())

	h.Stop()

	require.Equal(t, spi.StateStopped, h.State())
}

func TestHandler_HandleCreateActivity(t *testing.T) {
	cfg := &Config{
		ServiceName: "service1",
	}

	h := New(cfg, spi.WithUndeliverableHandler(mocks.NewUndeliverableHandler()))
	require.NotNil(t, h)

	h.Start()
	defer h.Stop()

	activityChan := h.Subscribe()

	var (
		mutex       sync.Mutex
		gotActivity *vocab.ActivityType
	)

	go func() {
		for activity := range activityChan {
			mutex.Lock()
			gotActivity = activity
			mutex.Unlock()
		}
	}()

	t.Run("Success", func(t *testing.T) {
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

		service1IRI := mustParseURL("http://localhost:8301/services/service1")
		service2IRI := mustParseURL("http://localhost:8302/services/service2")

		create := vocab.NewCreateActivity(newActivityID(service1IRI.String()),
			vocab.NewObjectProperty(vocab.WithObject(obj)),
			vocab.WithTarget(targetProperty),
			vocab.WithContext(vocab.ContextOrb),
			vocab.WithTo(service2IRI),
		)

		require.NoError(t, h.HandleActivity(create))

		time.Sleep(50 * time.Millisecond)

		mutex.Lock()
		require.Equal(t, create, gotActivity)
		mutex.Unlock()
	})

	t.Run("Unsupported activity", func(t *testing.T) {
		activity := &vocab.ActivityType{
			ObjectType: vocab.NewObject(vocab.WithType(vocab.Type("unsupported_type"))),
		}
		err := h.HandleActivity(activity)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported activity type")
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
