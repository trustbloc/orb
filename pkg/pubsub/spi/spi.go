/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

import "time"

// UndeliverableTopic is the topic to which to post undeliverable messages.
const UndeliverableTopic = "orb.undeliverable.activities"

// Options contains publisher/subscriber options.
type Options struct {
	PoolSize      int
	DeliveryDelay time.Duration
}

// Option specifies a publisher/subscriber option.
type Option func(option *Options)

// WithPool sets the pool size.
func WithPool(size int) Option {
	return func(option *Options) {
		option.PoolSize = size
	}
}

// WithDeliveryDelay sets the delivery delay.
// Note: Not all message brokers support this option.
func WithDeliveryDelay(delay time.Duration) Option {
	return func(option *Options) {
		option.DeliveryDelay = delay
	}
}
