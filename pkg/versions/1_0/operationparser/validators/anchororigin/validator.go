/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anchororigin

import (
	"fmt"
	"net/url"
	"time"

	"github.com/bluele/gcache"
)

type allowedOriginsStore interface {
	Get() ([]*url.URL, error)
}

// New creates anchor origin validator.
func New(allowedOriginsStore allowedOriginsStore, cacheExpiration time.Duration) *Validator {
	v := &Validator{
		allowedOriginsStore: allowedOriginsStore,
	}

	v.cache = gcache.New(0).LoaderFunc(v.load).Expiration(cacheExpiration).Build()

	return v
}

// Validator is anchor origin validator.
type Validator struct {
	allowedOriginsStore allowedOriginsStore
	cache               gcache.Cache
}

// Validate validates anchor origin object.
func (v *Validator) Validate(obj interface{}) error {
	if obj == nil {
		return fmt.Errorf("anchor origin must be specified")
	}

	allowed, err := v.allowedOrigins()
	if err != nil {
		return err
	}

	// if allowed origins contains wild-card '*' any origin is allowed
	_, ok := allowed["*"]
	if ok {
		return nil
	}

	var val string

	switch t := obj.(type) {
	case string:
		val = obj.(string)
	default:
		return fmt.Errorf("anchor origin type not supported %T", t)
	}

	_, ok = allowed[val]
	if !ok {
		return fmt.Errorf("origin %s is not supported", val)
	}

	return nil
}

func (v *Validator) allowedOrigins() (map[string]struct{}, error) {
	allowedItems, err := v.cache.Get(nil)
	if err != nil {
		return nil, err
	}

	allowed, ok := allowedItems.(map[string]struct{})
	if !ok {
		// If this happens then it's a bug.
		panic("allowed items should be map[string]struct{}")
	}

	return allowed, nil
}

func (v *Validator) load(interface{}) (interface{}, error) {
	allowed, err := v.allowedOriginsStore.Get()
	if err != nil {
		return nil, fmt.Errorf("load from store: %w", err)
	}

	return sliceToMap(allowed), nil
}

func sliceToMap(uris []*url.URL) map[string]struct{} {
	// convert slice to map
	values := make(map[string]struct{})
	for _, uri := range uris {
		values[uri.String()] = struct{}{}
	}

	return values
}
