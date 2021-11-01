/*
MIT License

Copyright (c) 2019 Three Dots Labs

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package amqp

import (
	"encoding/json"
	"testing"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-amqp/pkg/amqp"
	"github.com/ThreeDotsLabs/watermill/message"
	stdAmqp "github.com/streadway/amqp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultMarshaler(t *testing.T) {
	marshaler := DefaultMarshaler{}

	msg := message.NewMessage(watermill.NewUUID(), []byte("payload"))
	msg.Metadata.Set("foo", "bar")
	msg.Metadata.Set("x-death",
		`[{"count":1,"exchange":"some_exchange","queue":"some_queue","reason":"rejected","routing-keys":["some_queue"],"time":"2021-10-25T17:26:24Z"}]`) //nolint:lll

	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	_, headerExists := marshaled.Headers[amqp.DefaultMessageUUIDHeaderKey]
	assert.True(t, headerExists, "header %s doesn't exist", amqp.DefaultMessageUUIDHeaderKey)

	header, headerExists := marshaled.Headers["x-death"]
	require.True(t, headerExists, "header %s doesn't exist", "x-death")

	require.NotNil(t, header)

	arrHeader, ok := header.([]interface{})
	require.True(t, ok)
	require.Len(t, arrHeader, 1)

	xDeathValues, ok := arrHeader[0].(stdAmqp.Table)
	require.True(t, ok)

	count, ok := xDeathValues["count"]
	require.True(t, ok)
	require.Equal(t, float64(1), count)

	routingKeys, ok := xDeathValues["routing-keys"]
	require.True(t, ok)

	routingKeysArr, ok := routingKeys.([]interface{})
	require.True(t, ok)
	require.Len(t, routingKeysArr, 1)
	require.Equal(t, "some_queue", routingKeysArr[0])

	unmarshaledMsg, err := marshaler.Unmarshal(publishingToDelivery(&marshaled))
	require.NoError(t, err)

	assert.True(t, msg.Equals(unmarshaledMsg))
	assert.Equal(t, marshaled.DeliveryMode, stdAmqp.Persistent)
}

func TestDefaultMarshaler_without_message_uuid(t *testing.T) {
	marshaler := DefaultMarshaler{}

	msg := message.NewMessage(watermill.NewUUID(), nil)
	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	delete(marshaled.Headers, amqp.DefaultMessageUUIDHeaderKey)

	unmarshaledMsg, err := marshaler.Unmarshal(publishingToDelivery(&marshaled))
	require.NoError(t, err)

	assert.Empty(t, unmarshaledMsg.UUID)
}

func TestDefaultMarshaler_configured_message_uuid_header(t *testing.T) {
	headerKey := "custom_msg_uuid"
	marshaler := DefaultMarshaler{MessageUUIDHeaderKey: headerKey}

	msg := message.NewMessage(watermill.NewUUID(), nil)
	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	_, headerExists := marshaled.Headers[headerKey]
	assert.True(t, headerExists, "header %s doesn't exist", headerKey)

	unmarshaledMsg, err := marshaler.Unmarshal(publishingToDelivery(&marshaled))
	require.NoError(t, err)

	assert.Equal(t, msg.UUID, unmarshaledMsg.UUID)
}

func TestDefaultMarshaler_not_persistent(t *testing.T) {
	marshaler := DefaultMarshaler{NotPersistentDeliveryMode: true}

	msg := message.NewMessage(watermill.NewUUID(), []byte("payload"))
	msg.Metadata.Set("foo", "bar")

	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	assert.EqualValues(t, marshaled.DeliveryMode, 0)
}

func TestDefaultMarshaler_postprocess_publishing(t *testing.T) {
	marshaler := DefaultMarshaler{
		PostprocessPublishing: func(publishing stdAmqp.Publishing) stdAmqp.Publishing {
			publishing.CorrelationId = "correlation"
			publishing.ContentType = "application/json"

			return publishing
		},
	}

	msg := message.NewMessage(watermill.NewUUID(), []byte("payload"))
	msg.Metadata.Set("foo", "bar")

	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	assert.Equal(t, marshaled.CorrelationId, "correlation")
	assert.Equal(t, marshaled.ContentType, "application/json")
}

func TestDefaultMarshaler_metadata(t *testing.T) {
	marshaler := DefaultMarshaler{
		PostprocessPublishing: func(publishing stdAmqp.Publishing) stdAmqp.Publishing {
			publishing.CorrelationId = "correlation"
			publishing.ContentType = "application/json"

			return publishing
		},
	}

	msg := message.NewMessage(watermill.NewUUID(), []byte("payload"))
	msg.Metadata.Set("foo", "bar")
	msg.Metadata.Set("x-death",
		`[{"count":1,"exchange":"orb.exchange","queue":"outbox_activities","reason":"rejected","routing-keys":["outbox_activities"],"time":"2021-10-25T17:26:24Z"}]`) //nolint:lll

	marshaled, err := marshaler.Marshal(msg)
	require.NoError(t, err)

	assert.Equal(t, marshaled.CorrelationId, "correlation")
	assert.Equal(t, marshaled.ContentType, "application/json")
}

func publishingToDelivery(marshaled *stdAmqp.Publishing) stdAmqp.Delivery {
	return stdAmqp.Delivery{
		Body:    marshaled.Body,
		Headers: marshaled.Headers,
	}
}

func TestUnmarshal(t *testing.T) {
	var arrayValue []interface{}

	err := json.Unmarshal([]byte(`["value1","value2"]`), &arrayValue)
	require.NoError(t, err)
	require.Len(t, arrayValue, 2)

	err = json.Unmarshal([]byte(`xxx`), &arrayValue)
	require.Error(t, err)

	err = json.Unmarshal([]byte(``), &arrayValue)
	require.Error(t, err)

	err = json.Unmarshal(nil, &arrayValue)
	require.Error(t, err)
}
