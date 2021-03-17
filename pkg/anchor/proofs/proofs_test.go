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
    "coreIndex": "QmeKVo2aASdByo5eEtHsQ53Edizu8LsYRs4DMQcqytEBv8",
    "namespace": "did:sidetree",
    "operationCount": 1,
    "previousAnchors": {
      "EiBOAYRI3yUpwuZ_wYcJB57S3Pk0JMiK0_T9_dr1Maa4JQ": "QmeahiopyNSmCwEyGFmEQrtCaQSr67sP7aTiU8tfezMKb6"
    },
    "version": 0
  },
  "id": "http://peer1.com/vc/bd832ff3-446d-4a64-b11d-52bc3b59a922",
  "issuanceDate": "2021-03-17T20:01:09.3303708Z",
  "issuer": "http://peer1.com",
  "proof": {
    "created": "2021-03-17T20:01:09.3323119Z",
    "domain": "domain.com",
    "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..81HnKImSkOGFw9Uzux38FwYkUBnvbhLaD3rexlIu-n-MEOIIAgJ_CnI6mekB1_cJVo5H_agzFwFjN50wJmrhBQ",
    "proofPurpose": "assertionMethod",
    "type": "Ed25519Signature2018",
    "verificationMethod": "did:web:abc#CvSyX0VxMCbg-UiYpAVd9OmhaFBXBr5ISpv2RZ2c9DY"
  },
  "type": "VerifiableCredential"
}`
