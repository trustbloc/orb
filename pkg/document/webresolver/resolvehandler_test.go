/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webresolver

//go:generate counterfeiter -o ./mocks/orbresolver.gen.go --fake-name OrbResolver . orbResolver

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/document/webresolver/mocks"
	orbmocks "github.com/trustbloc/orb/pkg/mocks"
)

const (
	orbPrefix           = "did:orb"
	orbUnpublishedLabel = "uAAA"

	testDomain = "https://example.com"
	testSuffix = "suffix"
)

func TestResolveHandler_Resolve(t *testing.T) {
	testDomainURL, err := url.Parse(testDomain)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		testDoc, err := getTestDoc()
		require.NoError(t, err)

		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(&document.ResolutionResult{Document: testDoc}, nil)

		handler := NewResolveHandler(testDomainURL,
			orbPrefix, orbUnpublishedLabel, orbResolver,
			&orbmocks.MetricsProvider{})

		response, err := handler.ResolveDocument(testSuffix)
		require.NoError(t, err)
		require.NotNil(t, response)
	})

	t.Run("error - domain not in alsoKnownAs", func(t *testing.T) {
		testDoc, err := getTestDoc()
		require.NoError(t, err)

		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(&document.ResolutionResult{Document: testDoc}, nil)

		otherDomainURL, err := url.Parse("https://other.com")
		require.NoError(t, err)

		handler := NewResolveHandler(otherDomainURL,
			orbPrefix, orbUnpublishedLabel, orbResolver,
			&orbmocks.MetricsProvider{})

		response, err := handler.ResolveDocument("suffix")
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "id[did:web:other.com:identity:suffix] not found in alsoKnownAs")
	})

	t.Run("error - orb resolver error", func(t *testing.T) {
		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(nil, fmt.Errorf("orb resolver error"))

		handler := NewResolveHandler(testDomainURL,
			orbPrefix, orbUnpublishedLabel, orbResolver,
			&orbmocks.MetricsProvider{})

		response, err := handler.ResolveDocument(testSuffix)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "orb resolver error")
	})

	t.Run("error - orb resolver not found error", func(t *testing.T) {
		orbResolver := &mocks.OrbResolver{}
		orbResolver.ResolveDocumentReturns(nil, fmt.Errorf("not found"))

		handler := NewResolveHandler(testDomainURL,
			orbPrefix, orbUnpublishedLabel, orbResolver,
			&orbmocks.MetricsProvider{})

		response, err := handler.ResolveDocument(testSuffix)
		require.Error(t, err)
		require.Nil(t, response)
		require.Contains(t, err.Error(), "document not found")
	})
}

func getTestDoc() (document.Document, error) {
	didDoc := make(document.Document)
	didDoc["alsoKnownAs"] = []string{"did:web:example.com:identity:suffix"}
	didDoc["id"] = "did:orb:cid:suffix"

	didDocBytes, err := didDoc.Bytes()
	if err != nil {
		return nil, err
	}

	var expected document.Document

	err = json.Unmarshal(didDocBytes, &expected)
	if err != nil {
		return nil, err
	}

	return expected, nil
}
