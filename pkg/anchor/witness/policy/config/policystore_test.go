/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/store/mocks"
)

const testPolicy = "MinPercent(50,system) AND MinPercent(50,batch)"

func TestStore_PutPolicy(t *testing.T) {
	t.Run("PutPolicy -> success", func(t *testing.T) {
		s := NewPolicyStore(&mocks.Store{})
		require.NotNil(t, s)
		require.NoError(t, s.PutPolicy(testPolicy))
	})

	t.Run("PutPolicy -> store error", func(t *testing.T) {
		errExpected := errors.New("injected store error")

		ms := &mocks.Store{}
		ms.PutReturns(errExpected)

		s := NewPolicyStore(ms)
		require.NotNil(t, s)

		err := s.PutPolicy(testPolicy)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("PutPolicy -> marshal error", func(t *testing.T) {
		errExpected := errors.New("injected marshal error")

		s := NewPolicyStore(&mocks.Store{})
		require.NotNil(t, s)

		s.marshal = func(v interface{}) ([]byte, error) {
			return nil, errExpected
		}

		err := s.PutPolicy(testPolicy)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})
}

func TestStore_GetPolicy(t *testing.T) {
	t.Run("GetPolicy -> success", func(t *testing.T) {
		cfgBytes, err := json.Marshal(&policyCfg{Policy: testPolicy})
		require.NoError(t, err)

		ms := &mocks.Store{}
		ms.GetReturns(cfgBytes, nil)

		s := NewPolicyStore(ms)
		require.NotNil(t, s)

		policy, err := s.GetPolicy()
		require.NoError(t, err)
		require.Equal(t, testPolicy, policy)
	})

	t.Run("GetPolicy -> store error", func(t *testing.T) {
		errExpected := errors.New("injected get error")

		ms := &mocks.Store{}
		ms.GetReturns(nil, errExpected)

		s := NewPolicyStore(ms)
		require.NotNil(t, s)

		policy, err := s.GetPolicy()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, policy)
	})

	t.Run("GetPolicy -> unmarshal error", func(t *testing.T) {
		errExpected := errors.New("injected unmarshal error")

		s := NewPolicyStore(&mocks.Store{})
		require.NotNil(t, s)

		s.unmarshal = func(data []byte, v interface{}) error {
			return errExpected
		}

		policy, err := s.GetPolicy()
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Empty(t, policy)
	})
}
