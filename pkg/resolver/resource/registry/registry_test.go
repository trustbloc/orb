/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package registry

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
)

const (
	testSuffix = "suffix"
	testOrigin = "origin"

	testCID = "cid"
	testNS  = "did:orb"

	testID = testNS + ":" + testCID + ":" + testSuffix
)

func TestNew(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New()
		require.NotNil(t, registry)
	})
	t.Run("test new with resource info provider", func(t *testing.T) {
		registry := New(WithResourceInfoProvider(&mockResourceInfoProvider{}))
		require.NotNil(t, registry)
	})
}

func TestRegistry_GetResourceInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		info := make(Metadata)
		info[AnchorURIProperty] = testCID
		info[AnchorOriginProperty] = testOrigin

		registry := New(WithResourceInfoProvider(&mockResourceInfoProvider{Namespace: testNS, Info: info}))

		info, err := registry.GetResourceInfo(testID)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, info[AnchorURIProperty], testCID)
		require.Equal(t, info[AnchorOriginProperty], testOrigin)
	})

	t.Run("error - resource not supported", func(t *testing.T) {
		registry := New()

		info, err := registry.GetResourceInfo(testID)
		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "resource 'did:orb:cid:suffix' not supported")
	})

	t.Run("error - get resource info error", func(t *testing.T) {
		provider := &mockResourceInfoProvider{Namespace: testNS, Err: fmt.Errorf("resource info provider error")}

		registry := New(WithResourceInfoProvider(provider))

		info, err := registry.GetResourceInfo(testID)
		require.Error(t, err)
		require.Nil(t, info)
		require.Contains(t, err.Error(), "failed to get resource[did:orb:cid:suffix] info: resource info provider error")
	})
}

type mockResourceInfoProvider struct {
	Namespace string
	Err       error
	Info      Metadata
}

// GetResourceInfo will mock getting resource info.
func (m *mockResourceInfoProvider) GetResourceInfo(id string) (Metadata, error) {
	if m.Err != nil {
		return nil, m.Err
	}

	return m.Info, nil
}

// Accept accepts resource id.
func (m *mockResourceInfoProvider) Accept(id string) bool {
	return strings.HasPrefix(id, m.Namespace+docutil.NamespaceDelimiter)
}
