/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package models

import "time"

// Endpoint include info about endpoint.
type Endpoint struct {
	ResolutionEndpoints []string
	OperationEndpoints  []string
	MinResolvers        int
	MaxAge              uint `json:"-"`
}

// CacheLifetime returns the cache lifetime of the endpoint config file before it needs to be checked for an update.
func (c Endpoint) CacheLifetime() (time.Duration, error) {
	return time.Duration(c.MaxAge) * time.Second, nil
}
