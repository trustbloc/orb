/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didanchorinfo

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"

	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry/didanchorinfo/mocks"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testSuffix = "suffix"
	testOrigin = "origin"

	testCID = "cid"
	testNS  = "did:orb"

	testID = testNS + ":" + testCID + ":" + testSuffix
)

//go:generate counterfeiter -o ./mocks/operationprocessor.gen.go --fake-name OperationProcessor . operationProcessor

func TestNew(t *testing.T) {
	didOriginHandler := New(testNS, nil, nil)
	require.NotNil(t, didOriginHandler)
}

func TestDidAnchorInfo_GetResourceInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)

		operationProcessor := &mocks.OperationProcessor{}
		operationProcessor.ResolveReturns(&protocol.ResolutionModel{AnchorOrigin: testOrigin}, nil)

		didAnchoringProvider := New(testNS, store, operationProcessor)
		require.NotNil(t, didAnchoringProvider)

		info, err := didAnchoringProvider.GetResourceInfo(testID)
		require.NoError(t, err)

		require.Equal(t, testOrigin, info[registry.AnchorOriginProperty])
		require.Equal(t, testCID, info[registry.AnchorURIProperty])
	})

	t.Run("error - suffix not provided", func(t *testing.T) {
		didAnchoringProvider := New(testNS, nil, nil)
		require.NotNil(t, didAnchoringProvider)

		info, err := didAnchoringProvider.GetResourceInfo(testID + ":")
		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "did suffix is empty")
	})

	t.Run("error - not found error", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		operationProcessor := &mocks.OperationProcessor{}
		operationProcessor.ResolveReturns(&protocol.ResolutionModel{AnchorOrigin: testOrigin}, nil)

		didAnchoringProvider := New(testNS, store, operationProcessor)
		require.NotNil(t, didAnchoringProvider)

		info, err := didAnchoringProvider.GetResourceInfo(testID)
		require.Equal(t, ErrDataNotFound, err)
		require.Nil(t, info)
	})

	t.Run("error - did anchor store error", func(t *testing.T) {
		mockStore := &storemocks.Store{}
		mockStore.GetReturns(nil, fmt.Errorf("get error"))

		mockProvider := &storemocks.Provider{}
		mockProvider.OpenStoreReturns(mockStore, nil)

		store, err := didanchorstore.New(mockProvider)
		require.NoError(t, err)

		operationProcessor := &mocks.OperationProcessor{}
		operationProcessor.ResolveReturns(&protocol.ResolutionModel{AnchorOrigin: testOrigin}, nil)

		didAnchoringProvider := New(testNS, store, operationProcessor)
		require.NotNil(t, didAnchoringProvider)

		info, err := didAnchoringProvider.GetResourceInfo(testID)
		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "get error")
	})

	t.Run("error - operation processor error", func(t *testing.T) {
		store, err := didanchorstore.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.PutBulk([]string{testSuffix}, testCID)
		require.NoError(t, err)

		operationProcessor := &mocks.OperationProcessor{}
		operationProcessor.ResolveReturns(nil, fmt.Errorf("operation processor error"))

		didAnchoringProvider := New(testNS, store, operationProcessor)
		require.NotNil(t, didAnchoringProvider)

		info, err := didAnchoringProvider.GetResourceInfo(testID)
		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "operation processor error")
	})
}

func TestDidAnchorInfo_Accept(t *testing.T) {
	t.Run("success - true (id starts with namespace)", func(t *testing.T) {
		didAnchoringProvider := New(testNS, nil, nil)
		require.NotNil(t, didAnchoringProvider)

		ok := didAnchoringProvider.Accept(testID)
		require.True(t, ok)
	})

	t.Run("success - false (id does't start with namespace", func(t *testing.T) {
		didAnchoringProvider := New(testNS, nil, nil)
		require.NotNil(t, didAnchoringProvider)

		ok := didAnchoringProvider.Accept("did:doc:cid:suffix")
		require.False(t, ok)
	})

	t.Run("success - false (invalid did format - number of parts)", func(t *testing.T) {
		didAnchoringProvider := New(testNS, nil, nil)
		require.NotNil(t, didAnchoringProvider)

		ok := didAnchoringProvider.Accept("did:orb:suffix")
		require.False(t, ok)
	})
}
