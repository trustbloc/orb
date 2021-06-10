/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontext_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
)

func TestMustGetDefault(t *testing.T) {
	res := ldcontext.MustGetDefault()
	require.Len(t, res, 1)
	require.Equal(t, "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1", res[0].URL)
}

func TestMustGetExtra(t *testing.T) {
	res := ldcontext.MustGetExtra()
	require.Len(t, res, 2)
	require.Equal(t, "https://www.w3.org/2018/credentials/examples/v1", res[0].URL)
	require.Equal(t, "https://www.w3.org/ns/odrl.jsonld", res[1].URL)
}
