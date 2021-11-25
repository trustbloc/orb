/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolutionverifier

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/metadata"

	"github.com/trustbloc/orb/pkg/document/mocks"
)

const (
	recoveryCommitment = "recovery-commitment"
	updateCommitment   = "update-commitment"
)

func TestResolveVerifier_Verify(t *testing.T) {
	t.Run("success - unpublished document", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(unpublishedRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb",
			WithUnpublishedLabel(unpublishedLabel),
			WithAnchorOrigins(nil),
			WithMethodContext(nil),
			WithEnableBase(false))
		require.NoError(t, err)

		err = handler.Verify(&rr)
		require.NoError(t, err)
	})

	t.Run("success - published document(one published and one unpublished operation)", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(publishedAndUnpublishedRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&rr)
		require.NoError(t, err)
	})

	t.Run("success - published document(multiple published and one unpublished operation)", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(multiplePublishedAndUnpublishedRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&rr)
		require.NoError(t, err)
	})

	t.Run("success - published document(just published operations)", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(publishedOperationsRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&rr)
		require.NoError(t, err)
	})

	t.Run("error - failed to unmarshal published operations", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		methodMetadata[document.PublishedOperationsProperty] = "published-ops"

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		input := document.ResolutionResult{DocumentMetadata: docMetadata}

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&input)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get published operations: failed to unmarshal")
	})

	t.Run("error - invalid document ID (unable to get suffix)", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		input := document.ResolutionResult{DocumentMetadata: docMetadata}

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&input)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to resolve document with provided operations: invalid number of parts[1] for Orb identifier")
	})

	t.Run("error - resolver error (create operation missing)", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		doc := make(document.Document)
		doc["id"] = "did:orb:hash:suffix"

		input := document.ResolutionResult{DocumentMetadata: docMetadata, Document: doc}

		handler, err := New("did:orb")
		require.NoError(t, err)

		err = handler.Verify(&input)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve document with provided operations: missing create operation")
	})

	t.Run("error - input and resolved documents don't match error", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(publishedOperationsRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb")
		require.NoError(t, err)

		opProcessor := &mocks.OperationProcessor{}
		opProcessor.ResolveReturns(&protocol.ResolutionModel{Doc: make(document.Document)}, nil)

		handler.processor = opProcessor

		err = handler.Verify(&rr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to check input resolution result against assembled resolution result")
	})
}

func TestCheckResponses(t *testing.T) {
	doc := make(document.Document)

	methodMetadata := make(map[string]interface{})
	methodMetadata[document.RecoveryCommitmentProperty] = recoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = updateCommitment

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata

	t.Run("success", func(t *testing.T) {
		err := checkResponses(&document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata},
			&document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata})
		require.NoError(t, err)
	})

	t.Run("error - different documents", func(t *testing.T) {
		resolved := make(document.Document)
		resolved["id"] = "some-id"

		err := checkResponses(&document.ResolutionResult{Document: doc, DocumentMetadata: docMetadata},
			&document.ResolutionResult{Document: resolved, DocumentMetadata: docMetadata})
		require.Error(t, err)
		require.Contains(t, err.Error(), "documents don't match")
	})

	t.Run("error - unable to check commitments", func(t *testing.T) {
		err := checkResponses(&document.ResolutionResult{Document: doc}, &document.ResolutionResult{Document: doc})
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing document metadata")
	})
}

func TestEqualDocuments(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		err := equalDocuments(make(document.Document), make(document.Document))
		require.NoError(t, err)
	})
	t.Run("error - marshal input document", func(t *testing.T) {
		err := equalDocuments(nil, make(document.Document))
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal canonical failed for input document")
	})
	t.Run("error - marshal resolved document", func(t *testing.T) {
		err := equalDocuments(make(document.Document), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "marshal canonical failed for resolved document")
	})
}

func TestEqualCommitments(t *testing.T) {
	methodMetadata := make(map[string]interface{})
	methodMetadata[document.RecoveryCommitmentProperty] = recoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = updateCommitment

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata

	t.Run("success", func(t *testing.T) {
		err := equalCommitments(docMetadata, docMetadata)
		require.NoError(t, err)
	})

	t.Run("error - input missing method metadata", func(t *testing.T) {
		err := equalCommitments(make(document.Metadata), docMetadata)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get input metadata: missing method metadata")
	})

	t.Run("error - resolved missing method metadata", func(t *testing.T) {
		err := equalCommitments(docMetadata, make(document.Metadata))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get resolved metadata: missing method metadata")
	})

	t.Run("error - missing update commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'updateCommitment' in resolved method metadata")
	})

	t.Run("error - missing recovery commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'recoveryCommitment' in resolved method metadata")
	})

	t.Run("error - different commitments (update)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = "invalid-commitment"

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "input and resolved update commitments don't match")
	})

	t.Run("error - different commitments (recovery)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = "invalid-commitment"
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalCommitments(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "input and resolved recovery commitments don't match")
	})
}

func TestGetOperations(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		ops, err := getOperations(docMetadata)
		require.NoError(t, err)
		require.Equal(t, len(unpublishedOps)+len(publishedOps), len(ops))
	})

	t.Run("error - failed to unmarshal published operations", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		unpublishedOps := []metadata.UnpublishedOperation{{Type: operation.TypeUpdate}}
		methodMetadata[document.UnpublishedOperationsProperty] = unpublishedOps

		methodMetadata[document.PublishedOperationsProperty] = "published-ops"

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		ops, err := getOperations(docMetadata)
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "failed to get published operations: failed to unmarshal")
	})

	t.Run("error - failed to unmarshal unpublished operations", func(t *testing.T) {
		methodMetadata := make(map[string]interface{})

		methodMetadata[document.UnpublishedOperationsProperty] = "unpublished-ops"

		publishedOps := []metadata.PublishedOperation{{Type: operation.TypeUpdate, CanonicalReference: "abc"}}
		methodMetadata[document.PublishedOperationsProperty] = publishedOps

		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = methodMetadata

		ops, err := getOperations(docMetadata)
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "failed to get unpublished operations: failed to unmarshal")
	})

	t.Run("no operations - wrong metadata type", func(t *testing.T) {
		docMetadata := make(document.Metadata)
		docMetadata[document.MethodProperty] = "invalid-type"

		ops, err := getOperations(docMetadata)
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "method metadata is wrong type[string]")
	})

	t.Run("no operations - empty metadata", func(t *testing.T) {
		ops, err := getOperations(make(document.Metadata))
		require.Error(t, err)
		require.Empty(t, ops)
		require.Contains(t, err.Error(), "missing method metadata")
	})
}

//nolint:lll
const unpublishedRR = `
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://w3id.org/security/suites/ed25519-2018/v1"
    ],
    "assertionMethod": [
      "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth"
    ],
    "authentication": [
      "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey"
    ],
    "id": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "service": [
      {
        "id": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#didcomm",
        "priority": 0,
        "recipientKeys": [
          "JDEByxZ4r86P523S3JEJpYMB5GS6qfeF2JDafJavvhgy"
        ],
        "routingKeys": [
          "2hRNMYoPUFYqf6Wu8vtzWRisoztTnDopcpi618dpD1c8"
        ],
        "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
        "type": "did-communication"
      }
    ],
    "verificationMethod": [
      {
        "controller": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
        "id": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
        "publicKeyJwk": {
          "crv": "P-256",
          "kty": "EC",
          "x": "sV0MyWQ1Z03dLEyVOMffQzp3Z25bQ_hdze7Am9hhgFA",
          "y": "meAu6OloYAvupdAehPcOFBaRM_4NHU0GanE3P9bp1Rk"
        },
        "type": "JsonWebKey2020"
      },
      {
        "controller": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
        "id": "did:orb:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth",
        "publicKeyBase58": "4V2eee3RE2nXmdf8t59caUJeckQ5ebChh3E7iQ8SFbUM",
        "type": "Ed25519VerificationKey2018"
      }
    ]
  },
  "didDocumentMetadata": {
    "equivalentId": [
      "did:orb:https:orb.domain4.com:uAAA:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ"
    ],
    "method": {
      "anchorOrigin": "https://orb.domain1.com",
      "published": false,
      "recoveryCommitment": "EiBXxlBZ4xsisY5XtBBtC32bxny5sPlwAsQotCWn9mIpFw",
      "unpublishedOperations": [
        {
          "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
          "protocolVersion": 0,
          "transactionTime": 1635519155,
          "type": "create"
        }
      ],
      "updateCommitment": "EiDOeUN2rx3T9-48s-3qrv6bObQqEjJU9mQZOfJ3E3rMEg"
    }
  }
}`

//nolint:lll
const publishedAndUnpublishedRR = `
{
 "@context": "https://w3id.org/did-resolution/v1",
 "didDocument": {
  "@context": [
   "https://www.w3.org/ns/did/v1",
   "https://w3id.org/security/suites/jws-2020/v1",
   "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "assertionMethod": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth"
  ],
  "authentication": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey"
  ],
  "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "service": [
   {
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#didcomm",
    "priority": 0,
    "recipientKeys": [
     "JDEByxZ4r86P523S3JEJpYMB5GS6qfeF2JDafJavvhgy"
    ],
    "routingKeys": [
     "2hRNMYoPUFYqf6Wu8vtzWRisoztTnDopcpi618dpD1c8"
    ],
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
    "type": "did-communication"
   }
  ],
  "verificationMethod": [
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
    "publicKeyJwk": {
     "crv": "P-256",
     "kty": "EC",
     "x": "sV0MyWQ1Z03dLEyVOMffQzp3Z25bQ_hdze7Am9hhgFA",
     "y": "meAu6OloYAvupdAehPcOFBaRM_4NHU0GanE3P9bp1Rk"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth",
    "publicKeyBase58": "4V2eee3RE2nXmdf8t59caUJeckQ5ebChh3E7iQ8SFbUM",
    "type": "Ed25519VerificationKey2018"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   }
  ]
 },
 "didDocumentMetadata": {
  "canonicalId": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "equivalentId": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ"
  ],
  "method": {
   "anchorOrigin": "https://orb.domain1.com",
   "published": true,
   "publishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "canonicalReference": "uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A",
     "equivalentReferences": [
      "hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E",
      "https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519160,
     "type": "create"
    }
   ],
   "recoveryCommitment": "EiBXxlBZ4xsisY5XtBBtC32bxny5sPlwAsQotCWn9mIpFw",
   "unpublishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
     "protocolVersion": 0,
     "transactionTime": 1635519161,
     "type": "update"
    }
   ],
   "updateCommitment": "EiD6niVk2oqCnu8s2dPXXXUXh_rQC_bKtFJcbL_3Hv7fFQ"
  }
 }
}
`

//nolint:lll
const multiplePublishedAndUnpublishedRR = `
{
 "@context": "https://w3id.org/did-resolution/v1",
 "didDocument": {
  "@context": [
   "https://www.w3.org/ns/did/v1",
   "https://w3id.org/security/suites/jws-2020/v1",
   "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "assertionMethod": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth"
  ],
  "authentication": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#secondKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#thirdKey"
  ],
  "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "service": [
   {
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#didcomm",
    "priority": 0,
    "recipientKeys": [
     "JDEByxZ4r86P523S3JEJpYMB5GS6qfeF2JDafJavvhgy"
    ],
    "routingKeys": [
     "2hRNMYoPUFYqf6Wu8vtzWRisoztTnDopcpi618dpD1c8"
    ],
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
    "type": "did-communication"
   }
  ],
  "verificationMethod": [
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
    "publicKeyJwk": {
     "crv": "P-256",
     "kty": "EC",
     "x": "sV0MyWQ1Z03dLEyVOMffQzp3Z25bQ_hdze7Am9hhgFA",
     "y": "meAu6OloYAvupdAehPcOFBaRM_4NHU0GanE3P9bp1Rk"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth",
    "publicKeyBase58": "4V2eee3RE2nXmdf8t59caUJeckQ5ebChh3E7iQ8SFbUM",
    "type": "Ed25519VerificationKey2018"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#secondKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#thirdKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   }
  ]
 },
 "didDocumentMetadata": {
  "canonicalId": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "equivalentId": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ"
  ],
  "method": {
   "anchorOrigin": "https://orb.domain1.com",
   "published": true,
   "publishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "canonicalReference": "uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A",
     "equivalentReferences": [
      "hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E",
      "https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519160,
     "type": "create"
    },
    {
     "canonicalReference": "uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA",
     "equivalentReferences": [
      "hl:uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpQTFWM09CZlpyeVhxWlhQa0tTRnBKMDlSVTdnVEF1SENqOHVGakVpRzczT0E",
      "https:shared.domain.com:uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519166,
     "type": "update"
    },
    {
     "canonicalReference": "uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q",
     "equivalentReferences": [
      "hl:uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpQ1doLTRZUWVVRXpwVVZOZW42TjhYcHZJalVDMTV5clRrVmhKbUM0cWtYMFE",
      "https:shared.domain.com:uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InNlY29uZEtleSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJQLTI1NksiLCJrdHkiOiJFQyIsIngiOiJQVXltSXFkdEZfcXhhQXFQQUJTdy1DLW93VDFLWVlRYnNNS0ZNLUw5ZkpBIiwieSI6Im5NODRqREhDTU9UR1RoX1pkSHE0ZEJCZG80WjVQa0VPVzlqQTh6OElzR2MifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iXSwidHlwZSI6Ikpzb25XZWJLZXkyMDIwIn1dfV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJVeFlMclZVY1VNa21vZnVxMlhIbnBYbTlEeW9ZMTJmUXBGaldCQllTWEhBIn0sImRpZFN1ZmZpeCI6IkVpQnVHTDI5RUhlZW5XNzE3MmlHa2liXzlkSUtyQXpLN2phemdFUWpoRkNSa1EiLCJyZXZlYWxWYWx1ZSI6IkVpQ1lzVjdfdDJyLUk1Yktlemt5azUwYWJiN0I1SGprdGpWdkZzMnNqaDJ0UmciLCJzaWduZWREYXRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKaGJtTm9iM0pHY205dElqb3hOak0xTlRFNU1UWTNMQ0poYm1Ob2IzSlZiblJwYkNJNk1UWXpOVFV4T1RRMk55d2laR1ZzZEdGSVlYTm9Jam9pUldsRFJIZzBTMFUzYkRaMGEyMTJVaTFPT0VST2RqUlVlbkoyYkZoM1JubGFaREkzZDFGR1dFUjRhMDExWnlJc0luVndaR0YwWlV0bGVTSTZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SW1WbFRrdDFablZtUzFkUk0xSjNkbWxFTlRBdE5uUkhOMDVDVm5WdU9YZG5aVjlVTlUxM1kybDJSbU1pTENKNUlqb2lPVFJhVDA0M01WVkZURGhmVmpjNFJtSnlZVEJ1UldST1ZGRkxhVmxxTmpFMlFXdzRlV2RyT1VNMlJTSjlmUS5pOGNCSGlZSGhsVkkzc3laQ0R0eWk2MktJTTR0Z3Vkby15eWNWaktNNTlhWHYtRTNGU1JnNlFjTUNuem5aMHhBVm9vZ2NzOGRvRVpQOUdmSmd1OFlxZyIsInR5cGUiOiJ1cGRhdGUifQ==",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519173,
     "type": "update"
    }
   ],
   "recoveryCommitment": "EiBXxlBZ4xsisY5XtBBtC32bxny5sPlwAsQotCWn9mIpFw",
   "unpublishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InRoaXJkS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQV9zVXJjbWcxY0dfNkpmT2traF9fanZBMzNwNFZRSXNEUUxUOXJReVp2MGcifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlEVEJfNlNPall3YXUyRS1TRm5kRk1uU1U1d2lzd3B6Q3o5c1BpckhreEdfdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRneExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFE0TVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xETFZWYVRtcHlSbmh3Wm05SWFIaEdTMmhDU1ZOR2JYWjBVazFrWmt4UU9WaEtiMUJsTm5kWmIybFVRU0lzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJbk5UUnpkdWRrTlVSRFV0ZFdsMmRqQktORXRoUzNCWFJ6Z3hhbGc0WlRNM09ESktibUpMYTA4NFFWa2lMQ0o1SWpvaVZ6Wm9RUzFOZHpCMldYTnNaRUZvUm5walpsUXpXSGszY1VWdU5WTlFka2gyVm5ScE5HNXZNMDFvTkNKOWZRLl84TWtLbDZXMjNncDFZaEJ0LTNVZjRESnNLV0NLR0V1dzhEUFJLd3pxTDVtM0dScWlJOGtQVWFCTHM5T25ocjVYRlV6MFdVV25YallSemhfX2JTcnJRIiwidHlwZSI6InVwZGF0ZSJ9",
     "protocolVersion": 0,
     "transactionTime": 1635519181,
     "type": "update"
    }
   ],
   "updateCommitment": "EiA_sUrcmg1cG_6JfOkkh__jvA33p4VQIsDQLT9rQyZv0g"
  }
 }
}
`

//nolint:lll
const publishedOperationsRR = `
{
 "@context": "https://w3id.org/did-resolution/v1",
 "didDocument": {
  "@context": [
   "https://www.w3.org/ns/did/v1",
   "https://w3id.org/security/suites/jws-2020/v1",
   "https://w3id.org/security/suites/ed25519-2018/v1"
  ],
  "assertionMethod": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth"
  ],
  "authentication": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey",
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#secondKey"
  ],
  "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "service": [
   {
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#didcomm",
    "priority": 0,
    "recipientKeys": [
     "JDEByxZ4r86P523S3JEJpYMB5GS6qfeF2JDafJavvhgy"
    ],
    "routingKeys": [
     "2hRNMYoPUFYqf6Wu8vtzWRisoztTnDopcpi618dpD1c8"
    ],
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
    "type": "did-communication"
   }
  ],
  "verificationMethod": [
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#createKey",
    "publicKeyJwk": {
     "crv": "P-256",
     "kty": "EC",
     "x": "sV0MyWQ1Z03dLEyVOMffQzp3Z25bQ_hdze7Am9hhgFA",
     "y": "meAu6OloYAvupdAehPcOFBaRM_4NHU0GanE3P9bp1Rk"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#auth",
    "publicKeyBase58": "4V2eee3RE2nXmdf8t59caUJeckQ5ebChh3E7iQ8SFbUM",
    "type": "Ed25519VerificationKey2018"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#firstKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   },
   {
    "controller": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
    "id": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ#secondKey",
    "publicKeyJwk": {
     "crv": "P-256K",
     "kty": "EC",
     "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
     "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
    },
    "type": "JsonWebKey2020"
   }
  ]
 },
 "didDocumentMetadata": {
  "canonicalId": "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
  "equivalentId": [
   "did:orb:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ",
   "did:orb:https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:EiBuGL29EHeenW7172iGkib_9dIKrAzK7jazgEQjhFCRkQ"
  ],
  "method": {
   "anchorOrigin": "https://orb.domain1.com",
   "published": true,
   "publishedOperations": [
    {
     "anchorOrigin": "https://orb.domain1.com",
     "canonicalReference": "uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A",
     "equivalentReferences": [
      "hl:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpRHFCQkhNTkVaUWdkbzFqUnh2ZXpFSEFjM1Uxa1FRamRyVDd5NXliRmdsX0E",
      "https:shared.domain.com:uEiDqBBHMNEZQgdo1jRxvezEHAc3U1kQQjdrT7y5ybFgl_A"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519160,
     "type": "create"
    },
    {
     "canonicalReference": "uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA",
     "equivalentReferences": [
      "hl:uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpQTFWM09CZlpyeVhxWlhQa0tTRnBKMDlSVTdnVEF1SENqOHVGakVpRzczT0E",
      "https:shared.domain.com:uEiA1V3OBfZryXqZXPkKSFpJ09RU7gTAuHCj8uFjEiG73OA"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519166,
     "type": "update"
    },
    {
     "canonicalReference": "uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q",
     "equivalentReferences": [
      "hl:uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q:uoQ-BeEtodHRwczovL29yYi5kb21haW40LmNvbS9jYXMvdUVpQ1doLTRZUWVVRXpwVVZOZW42TjhYcHZJalVDMTV5clRrVmhKbUM0cWtYMFE",
      "https:shared.domain.com:uEiCWh-4YQeUEzpUVNen6N8XpvIjUC15yrTkVhJmC4qkX0Q"
     ],
     "operationRequest": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InNlY29uZEtleSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJQLTI1NksiLCJrdHkiOiJFQyIsIngiOiJQVXltSXFkdEZfcXhhQXFQQUJTdy1DLW93VDFLWVlRYnNNS0ZNLUw5ZkpBIiwieSI6Im5NODRqREhDTU9UR1RoX1pkSHE0ZEJCZG80WjVQa0VPVzlqQTh6OElzR2MifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iXSwidHlwZSI6Ikpzb25XZWJLZXkyMDIwIn1dfV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJVeFlMclZVY1VNa21vZnVxMlhIbnBYbTlEeW9ZMTJmUXBGaldCQllTWEhBIn0sImRpZFN1ZmZpeCI6IkVpQnVHTDI5RUhlZW5XNzE3MmlHa2liXzlkSUtyQXpLN2phemdFUWpoRkNSa1EiLCJyZXZlYWxWYWx1ZSI6IkVpQ1lzVjdfdDJyLUk1Yktlemt5azUwYWJiN0I1SGprdGpWdkZzMnNqaDJ0UmciLCJzaWduZWREYXRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKaGJtTm9iM0pHY205dElqb3hOak0xTlRFNU1UWTNMQ0poYm1Ob2IzSlZiblJwYkNJNk1UWXpOVFV4T1RRMk55d2laR1ZzZEdGSVlYTm9Jam9pUldsRFJIZzBTMFUzYkRaMGEyMTJVaTFPT0VST2RqUlVlbkoyYkZoM1JubGFaREkzZDFGR1dFUjRhMDExWnlJc0luVndaR0YwWlV0bGVTSTZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SW1WbFRrdDFablZtUzFkUk0xSjNkbWxFTlRBdE5uUkhOMDVDVm5WdU9YZG5aVjlVTlUxM1kybDJSbU1pTENKNUlqb2lPVFJhVDA0M01WVkZURGhmVmpjNFJtSnlZVEJ1UldST1ZGRkxhVmxxTmpFMlFXdzRlV2RyT1VNMlJTSjlmUS5pOGNCSGlZSGhsVkkzc3laQ0R0eWk2MktJTTR0Z3Vkby15eWNWaktNNTlhWHYtRTNGU1JnNlFjTUNuem5aMHhBVm9vZ2NzOGRvRVpQOUdmSmd1OFlxZyIsInR5cGUiOiJ1cGRhdGUifQ==",
     "protocolVersion": 0,
     "transactionNumber": 0,
     "transactionTime": 1635519173,
     "type": "update"
    }
   ],
   "recoveryCommitment": "EiBXxlBZ4xsisY5XtBBtC32bxny5sPlwAsQotCWn9mIpFw",
   "updateCommitment": "EiBUxYLrVUcUMkmofuq2XHnpXm9DyoY12fQpFjWBBYSXHA"
  }
 }
}`
