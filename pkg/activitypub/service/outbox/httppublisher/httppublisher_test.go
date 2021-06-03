/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package httppublisher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"testing"

	"github.com/ThreeDotsLabs/watermill"
	wmhttp "github.com/ThreeDotsLabs/watermill-http/pkg/http"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

func TestNew(t *testing.T) {
	p := New("service1", transport.Default())
	require.NotNil(t, p)
	require.NotNil(t, p.httpTransport)
	require.Equal(t, lifecycle.StateStarted, p.State())

	require.NoError(t, p.Close())
	require.Equal(t, lifecycle.StateStopped, p.State())
}

func TestPublisher_Publish(t *testing.T) {
	const serviceURL = "http://localhost:8100/services/service1"

	var mutex sync.RWMutex

	messagesReceived := make(map[string]*message.Message)

	httpServer := httpserver.New(":8100", "", "",
		newTestHandler("/services/service1", func(w http.ResponseWriter, req *http.Request) {
			payload, err := ioutil.ReadAll(req.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			msgID := req.Header.Get(wmhttp.HeaderUUID)
			if msgID == "" {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			msg := message.NewMessage(msgID, payload)

			metadata := req.Header.Get(wmhttp.HeaderMetadata)

			err = json.Unmarshal([]byte(metadata), &msg.Metadata)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)

				return
			}

			mutex.Lock()
			messagesReceived[msg.UUID] = msg
			mutex.Unlock()

			w.WriteHeader(http.StatusOK)
		}),
	)

	require.NoError(t, httpServer.Start())

	defer func() {
		require.NoError(t, httpServer.Stop(context.Background()))
	}()

	p := New("service1", transport.Default())
	require.NotNil(t, p)

	t.Run("Success", func(t *testing.T) {
		payload1 := []byte("payload1")
		payload2 := []byte("payload2")

		msg1 := message.NewMessage(watermill.NewUUID(), payload1)
		msg1.Metadata[MetadataSendTo] = serviceURL

		msg2 := message.NewMessage(watermill.NewUUID(), payload2)
		msg2.Metadata[MetadataSendTo] = serviceURL

		require.NoError(t, p.Publish("topic", msg1, msg2))

		mutex.RLock()
		m1, ok := messagesReceived[msg1.UUID]
		mutex.RUnlock()

		require.True(t, ok)
		require.Equal(t, payload1, []byte(m1.Payload))

		mutex.RLock()
		m2, ok := messagesReceived[msg2.UUID]
		mutex.RUnlock()

		require.True(t, ok)
		require.Equal(t, payload2, []byte(m2.Payload))
	})

	t.Run("NewRequest error", func(t *testing.T) {
		err := p.Publish("topic", message.NewMessage(watermill.NewUUID(), []byte("payload")))
		require.Error(t, err)
		require.Contains(t, err.Error(), "metadata [send_to] not found in message")
	})

	t.Run("BadRequest error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected request error")

		p.newRequestFunc = func(s string, m *message.Message) (*transport.Request, error) {
			return nil, errExpected
		}
		defer func() { p.newRequestFunc = p.newRequest }()

		err := p.Publish("topic", message.NewMessage(watermill.NewUUID(), []byte("payload")))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestNewRequest(t *testing.T) {
	const serviceURL = "http://localhost:8100/services/service1"

	p := New("service1", transport.Default())
	require.NotNil(t, p)

	t.Run("Success", func(t *testing.T) {
		payload1 := []byte("payload1")
		msg1 := message.NewMessage(watermill.NewUUID(), payload1)
		msg1.Metadata[MetadataSendTo] = serviceURL

		req, err := p.newRequest("", msg1)
		require.NoError(t, err)
		require.Equal(t, msg1.UUID, req.Header.Get(wmhttp.HeaderUUID))

		metadata := req.Header.Get(wmhttp.HeaderMetadata)
		require.NotEmpty(t, metadata)

		var md message.Metadata
		require.NoError(t, json.Unmarshal([]byte(metadata), &md))
		require.Equal(t, serviceURL, md[MetadataSendTo])
	})

	t.Run("No SendTo metadata", func(t *testing.T) {
		_, err := p.newRequest("", message.NewMessage(watermill.NewUUID(), []byte("payload")))
		require.EqualError(t, err, "metadata [send_to] not found in message")
	})

	t.Run("Invalid SendTo metadata", func(t *testing.T) {
		msg1 := message.NewMessage(watermill.NewUUID(), []byte("payload1"))
		msg1.Metadata[MetadataSendTo] = string([]byte{0x7F})

		_, err := p.newRequest("", msg1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid control character in URL")
	})

	t.Run("Marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		p.jsonMarshal = func(v interface{}) ([]byte, error) { return nil, errExpected }
		defer func() { p.jsonMarshal = nil }()

		payload1 := []byte("payload1")
		msg1 := message.NewMessage(watermill.NewUUID(), payload1)
		msg1.Metadata[MetadataSendTo] = serviceURL

		_, err := p.newRequest("", msg1)
		require.True(t, errors.Is(err, errExpected))
	})
}

type testHandler struct {
	path    string
	handler common.HTTPRequestHandler
}

func newTestHandler(path string, handler common.HTTPRequestHandler) *testHandler {
	return &testHandler{
		path:    path,
		handler: handler,
	}
}

func (m *testHandler) Path() string {
	return m.path
}

func (m *testHandler) Method() string {
	return http.MethodPost
}

func (m *testHandler) Handler() common.HTTPRequestHandler {
	return m.handler
}
