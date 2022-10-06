/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const policyKey = "witness-policy"

// Store implements the witness policy config store.
type Store struct {
	store     storage.Store
	marshal   func(v interface{}) ([]byte, error)
	unmarshal func(data []byte, v interface{}) error
}

// NewPolicyStore returns a new witness policy config store.
func NewPolicyStore(store storage.Store) *Store {
	return &Store{
		store:     store,
		marshal:   json.Marshal,
		unmarshal: json.Unmarshal,
	}
}

// PutPolicy stores the witness policy.
func (s *Store) PutPolicy(policyStr string) error {
	policyCfg := &policyCfg{
		Policy: policyStr,
	}

	valueBytes, err := s.marshal(policyCfg)
	if err != nil {
		return fmt.Errorf("marshal witness policy: %w", err)
	}

	err = s.store.Put(policyKey, valueBytes)
	if err != nil {
		return orberrors.NewTransientf("store witness policy: %w", err)
	}

	return nil
}

// GetPolicy returns the witness policy.
func (s *Store) GetPolicy() (string, error) {
	policyBytes, err := s.store.Get(policyKey)
	if err != nil {
		return "", err
	}

	policyCfg := &policyCfg{}

	err = s.unmarshal(policyBytes, &policyCfg)
	if err != nil {
		return "", fmt.Errorf("unmarshal witness policy: %w", err)
	}

	return policyCfg.Policy, nil
}

//nolint:tagliatelle
type policyCfg struct {
	Policy string `json:"Policy"`
}
