/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/discovery/did/mocks"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/client/models"
)

//go:generate counterfeiter -o ../mocks/didPublisher.gen.go --fake-name DIDPublisher . didPublisher
//go:generate counterfeiter -o ../mocks/endpointClient.gen.go --fake-name EndpointClient . endpointClient

const (
	testNS = "did:orb"
)

func TestDiscovery_RequestDiscovery(t *testing.T) {
	t.Run("success - ipfs", func(t *testing.T) {
		endpointClient := &mocks.EndpointClient{}
		retValue := &models.Endpoint{AnchorURI: "anchorURI", AnchorOrigin: "anchorOriginURI"}
		endpointClient.GetEndpointFromAnchorOriginReturns(retValue, nil)

		d := New(testNS, &mocks.DIDPublisher{}, endpointClient)

		err := d.RequestDiscovery("did:orb:ipfs:cid:suffix")
		require.NoError(t, err)
	})

	t.Run("success - webcas", func(t *testing.T) {
		endpointClient := &mocks.EndpointClient{}
		retValue := &models.Endpoint{AnchorURI: "anchorURI", AnchorOrigin: "anchorOriginURI"}
		endpointClient.GetEndpointFromAnchorOriginReturns(retValue, nil)

		d := New(testNS, &mocks.DIDPublisher{}, endpointClient)

		err := d.RequestDiscovery("did:orb:https:domain.com:cid:suffix")
		require.NoError(t, err)
	})

	t.Run("success - no cid hint", func(t *testing.T) {
		endpointClient := &mocks.EndpointClient{}
		retValue := &models.Endpoint{AnchorURI: "anchorURI", AnchorOrigin: "anchorOriginURI"}
		endpointClient.GetEndpointFromAnchorOriginReturns(retValue, nil)

		d := New(testNS, &mocks.DIDPublisher{}, endpointClient)

		err := d.RequestDiscovery("did:orb:cid:suffix")
		require.NoError(t, err)
	})

	t.Run("error - invalid did format", func(t *testing.T) {
		endpointClient := &mocks.EndpointClient{}
		retValue := &models.Endpoint{AnchorURI: "anchorURI", AnchorOrigin: "anchorOriginURI"}
		endpointClient.GetEndpointFromAnchorOriginReturns(retValue, nil)

		d := New(testNS, &mocks.DIDPublisher{}, endpointClient)

		err := d.RequestDiscovery("did:orb:cid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid number of parts[3] for Orb identifier")
	})

	t.Run("get cid from did", func(t *testing.T) {
		endpointClient := &mocks.EndpointClient{}
		endpointClient.GetEndpointFromAnchorOriginReturns(nil, fmt.Errorf("endpoint error"))

		d := New(testNS, &mocks.DIDPublisher{}, endpointClient)

		err := d.RequestDiscovery("did:orb:ipfs:abc:123")
		require.NoError(t, err)
	})
}
