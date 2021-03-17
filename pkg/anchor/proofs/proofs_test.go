/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proofs

import (
	"net/url"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/stretchr/testify/require"
)

const activityPubURL = "http://localhost/activityPubURL"

func TestNew(t *testing.T) {
	var vcChan chan *verifiable.Credential

	providers := &Providers{}

	apServiceIRI, err := url.Parse(activityPubURL)
	require.NoError(t, err)

	c := New(providers, vcChan, apServiceIRI)
	require.NotNil(t, c)
}

func TestClient_GetProofs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vcCh := make(chan *verifiable.Credential, 100)

		providers := &Providers{}

		apServiceIRI, err := url.Parse(activityPubURL)
		require.NoError(t, err)

		c := New(providers, vcCh, apServiceIRI)

		anchorVC, err := verifiable.ParseCredential([]byte(anchorCred), verifiable.WithDisabledProofCheck())
		require.NoError(t, err)

		err = c.RequestProofs(anchorVC, nil)
		require.NoError(t, err)
	})
}

//nolint:gochecknoglobals,lll
var anchorCred = `
{
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"credentialSubject": {
		"anchorString": "1.QmaevShHgc5s7bNnGKkQ98BdaKDNrsCTUV6rcwHr522tQB",
		"namespace": "did:sidetree",
		"previousTransactions": {
		"EiBAnjPBzHqAA-yONCU1HbGln-I0T-ZUPSIkkYAM6EwKKQ": "QmPEVPudBXM5XCoxoNUQiV466e7vD4XowohU8nRAhKJZ6f"
		},
		"version": 0
	},
	"id": "http://peer1.com/vc/85ef42f6-1019-40cc-ab3a-2b477681f5d8",
	"issuanceDate": "2021-03-10T16:34:17.9767297Z",
	"issuer": "http://peer1.com",
	"proof": {
		"created": "2021-03-10T16:34:17.9799878Z",
		"domain": "domain.com",
		"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yRt-VlWPDRq0jX-5iMYSfugJspbtmXZn3a9L011w8LI22WzpFZ5YQCTz6B09Stonywg_Xe6fwygG3IPQ5jreBg",
		"proofPurpose": "assertionMethod",
		"type": "Ed25519Signature2018",
		"verificationMethod": "did:web:abc#vaK33R-2ssibOOf2CS0RceLeT61Z2hpskHuEvDW7Hq0"
	},
	"type": "VerifiableCredential"
}`
