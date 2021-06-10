/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package spi

// UndeliverableTopic is the topic to which to post undeliverable messages.
const UndeliverableTopic = "undeliverable_activities"

// Options contains publisher/subscriber options.
type Options struct {
	PoolSize uint
}

// Option specifies a publisher/subscriber option.
type Option func(option *Options)

// WithPool sets the pool size.
func WithPool(size uint) Option {
	return func(option *Options) {
		option.PoolSize = size
	}
}
