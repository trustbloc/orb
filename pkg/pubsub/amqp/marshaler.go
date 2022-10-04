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
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/trustbloc/orb/internal/pkg/log"
)

const defaultMessageUUIDHeaderKey = "_watermill_message_uuid"

// DefaultMarshaler is a modified version of the marshaller in watermill-amqp. This marshaller adds support for
// dead-letter queue header values and also allows a message's expiration to be set in the header.
type DefaultMarshaler struct {
	// PostprocessPublishing can be used to make some extra processing with amqp.Publishing,
	// for example add CorrelationId and ContentType:
	//
	//  amqp.DefaultMarshaler{
	//		PostprocessPublishing: func(publishing stdAmqp.Publishing) stdAmqp.Publishing {
	//			publishing.CorrelationId = "correlation"
	//			publishing.ContentType = "application/json"
	//
	//			return publishing
	//		},
	//	}
	PostprocessPublishing func(amqp.Publishing) amqp.Publishing

	// When true, DeliveryMode will be not set to Persistent.
	//
	// DeliveryMode Transient means higher throughput, but messages will not be
	// restored on broker restart. The delivery mode of publishings is unrelated
	// to the durability of the queues they reside on. Transient messages will
	// not be restored to durable queues, persistent messages will be restored to
	// durable queues and lost on non-durable queues during server restart.
	NotPersistentDeliveryMode bool

	// Header used to store and read message UUID.
	//
	// If value is empty, defaultMessageUUIDHeaderKey value is used.
	// If header doesn't exist, empty value is passed as message UUID.
	MessageUUIDHeaderKey string
}

// Marshal marshals a message.
func (d DefaultMarshaler) Marshal(msg *message.Message) (amqp.Publishing, error) {
	headers := make(amqp.Table, len(msg.Metadata)+1) // metadata + plus uuid

	logger.Debug("Marshalling message with metadata", log.WithMessageID(msg.UUID),
		log.WithMetadata(msg.Metadata))

	for key, value := range msg.Metadata {
		if key == metadataExpiration {
			logger.Debug("Ignoring metadata property since it will be set in the message directly",
				log.WithProperty(key))

			continue
		}

		headerValue, err := unmarshalHeaderValue(value)
		if err != nil {
			return amqp.Publishing{}, fmt.Errorf("unmarshal value for metadata %s: %w", key, err)
		}

		headers[key] = headerValue
	}

	headers[d.computeMessageUUIDHeaderKey()] = msg.UUID

	publishing := amqp.Publishing{
		Body:       msg.Payload,
		Headers:    headers,
		Expiration: getExpiration(msg.Metadata),
	}
	if !d.NotPersistentDeliveryMode {
		publishing.DeliveryMode = amqp.Persistent
	}

	if d.PostprocessPublishing != nil {
		publishing = d.PostprocessPublishing(publishing)
	}

	return publishing, nil
}

// Unmarshal unmarshals a message.
//nolint:gocritic
func (d DefaultMarshaler) Unmarshal(amqpMsg amqp.Delivery) (*message.Message, error) {
	msgUUIDStr, err := d.unmarshalMessageUUID(amqpMsg.Headers)
	if err != nil {
		return nil, err
	}

	msg := message.NewMessage(msgUUIDStr, amqpMsg.Body)
	msg.Metadata = make(message.Metadata, len(amqpMsg.Headers)-1) // headers - minus uuid

	for key, value := range amqpMsg.Headers {
		if key == d.computeMessageUUIDHeaderKey() {
			continue
		}

		logger.Debug("Got metadata property", log.WithProperty(key), log.WithType(reflect.TypeOf(value).String()))

		msg.Metadata[key], err = marshalHeaderValue(value)
		if err != nil {
			return nil, fmt.Errorf("marshal header value for metadata [%s]: %w", key, err)
		}
	}

	return msg, nil
}

func (d DefaultMarshaler) unmarshalMessageUUID(headers amqp.Table) (string, error) {
	var msgUUIDStr string

	msgUUID, hasMsgUUID := headers[d.computeMessageUUIDHeaderKey()]
	if !hasMsgUUID {
		return "", nil
	}

	msgUUIDStr, hasMsgUUID = msgUUID.(string)
	if !hasMsgUUID {
		return "", fmt.Errorf("message UUID is not a string, but: %#v", msgUUID)
	}

	return msgUUIDStr, nil
}

func (d DefaultMarshaler) computeMessageUUIDHeaderKey() string {
	if d.MessageUUIDHeaderKey != "" {
		return d.MessageUUIDHeaderKey
	}

	return defaultMessageUUIDHeaderKey
}

func marshalHeaderValue(value interface{}) (string, error) {
	headerValue, ok := value.(string)
	if ok {
		return headerValue, nil
	}

	arrayValue, ok := value.([]interface{})
	if !ok {
		return "", fmt.Errorf("value is not a string or an array, but %#v", value)
	}

	// Marshal the table to JSON.
	valueBytes, err := json.Marshal(arrayValue)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}

	return string(valueBytes), nil
}

// unmarshalHeaderValue checks if the value is a JSON array value and, if so, unmarshals it and returns an array.
// Otherwise the given string value is returned.
func unmarshalHeaderValue(value string) (interface{}, error) {
	var arrayValue []interface{}

	err := json.Unmarshal([]byte(value), &arrayValue)
	if err != nil {
		// The header is a string.
		return value, nil //nolint:nilerr
	}

	// The header is an array.

	headerValue := make([]interface{}, len(arrayValue))

	for i, value := range arrayValue {
		tableValue, ok := value.(amqp.Table)
		if ok {
			headerValue[i] = tableValue
		} else {
			mapValue, ok := value.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("unsupported value type: %s", reflect.TypeOf(value))
			}

			tableValue = make(amqp.Table)
			for k, v := range mapValue {
				tableValue[k] = v
			}

			headerValue[i] = tableValue
		}
	}

	return headerValue, nil
}

func getExpiration(metadata message.Metadata) string {
	expirationValue, ok := metadata[metadataExpiration]
	if !ok {
		return ""
	}

	expirationDuration, err := time.ParseDuration(expirationValue)
	if err == nil {
		return strconv.FormatInt(expirationDuration.Milliseconds(), 10)
	}

	logger.Warn("Invalid value for metadata property. No expiration will be set.",
		log.WithValue(expirationValue), log.WithProperty(metadataExpiration), log.WithError(err))

	return ""
}
