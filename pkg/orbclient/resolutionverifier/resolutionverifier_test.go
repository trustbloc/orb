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

	anchorOriginDomain = "https://anchor-origin.domain.com"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		handler, err := New("did:orb",
			WithAnchorOrigins(nil),
			WithMethodContext(nil),
			WithEnableBase(false),
			WithProtocolVersions([]string{v1}),
			WithCurrentProtocolVersion(v1),
		)
		require.NoError(t, err)
		require.NotNil(t, handler)
	})
	t.Run("error - protocol versions", func(t *testing.T) {
		handler, err := New("did:orb",
			WithAnchorOrigins(nil),
			WithMethodContext(nil),
			WithEnableBase(false),
			WithProtocolVersions([]string{"0.1"}),
		)
		require.Error(t, err)
		require.Nil(t, handler)
		require.Contains(t, err.Error(), "client version factory for version [0.1] not found")
	})
	t.Run("error - protocol versions not provided", func(t *testing.T) {
		handler, err := New("did:orb",
			WithAnchorOrigins(nil),
			WithMethodContext(nil),
			WithEnableBase(false),
			WithProtocolVersions([]string{}),
		)
		require.Error(t, err)
		require.Nil(t, handler)
		require.Contains(t, err.Error(), "must provide at least one client version")
	})
}

func TestResolveVerifier_Verify(t *testing.T) {
	t.Run("success - unpublished document", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(unpublishedRR), &rr)
		require.NoError(t, err)

		handler, err := New("did:orb",
			WithAnchorOrigins(nil),
			WithMethodContext(nil),
			WithEnableBase(false),
			WithProtocolVersions([]string{v1}),
			WithCurrentProtocolVersion(v1),
		)
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

	t.Run("success - deactivated document", func(t *testing.T) {
		var rr document.ResolutionResult
		err := json.Unmarshal([]byte(deactivatedRR), &rr)
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
		require.Contains(t, err.Error(), "failed to resolve document with provided operations: create operation not found")
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

func TestEqualMetadata(t *testing.T) {
	methodMetadata := make(map[string]interface{})
	methodMetadata[document.RecoveryCommitmentProperty] = recoveryCommitment
	methodMetadata[document.UpdateCommitmentProperty] = updateCommitment
	methodMetadata[document.AnchorOriginProperty] = anchorOriginDomain

	docMetadata := make(document.Metadata)
	docMetadata[document.MethodProperty] = methodMetadata
	docMetadata[document.CanonicalIDProperty] = "canonical-id"

	t.Run("success", func(t *testing.T) {
		err := equalMetadata(docMetadata, docMetadata)
		require.NoError(t, err)
	})

	t.Run("success - invalid object means false for deactivate flag", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = updateCommitment
		md[document.AnchorOriginProperty] = anchorOriginDomain

		docMD := make(document.Metadata)
		docMD[document.DeactivatedProperty] = 123 // this should never happen - just for unit testing
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.NoError(t, err)
	})

	t.Run("error - input missing method metadata", func(t *testing.T) {
		err := equalMetadata(make(document.Metadata), docMetadata)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get input metadata: missing method metadata")
	})

	t.Run("error - resolved missing method metadata", func(t *testing.T) {
		err := equalMetadata(docMetadata, make(document.Metadata))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to get resolved metadata: missing method metadata")
	})

	t.Run("error - missing update commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.AnchorOriginProperty] = anchorOriginDomain
		md[document.RecoveryCommitmentProperty] = recoveryCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'updateCommitment' in resolved method metadata")
	})

	t.Run("error - missing recovery commitment", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.AnchorOriginProperty] = anchorOriginDomain
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing 'recoveryCommitment' in resolved method metadata")
	})

	t.Run("error - different commitments (update)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.AnchorOriginProperty] = anchorOriginDomain
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = "invalid-commitment"

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "input and resolved update commitments don't match")
	})

	t.Run("error - different commitments (recovery)", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.AnchorOriginProperty] = anchorOriginDomain
		md[document.RecoveryCommitmentProperty] = "invalid-commitment"
		md[document.UpdateCommitmentProperty] = updateCommitment

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(), "input and resolved recovery commitments don't match")
	})

	t.Run("error - different anchor origins", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = updateCommitment
		md[document.AnchorOriginProperty] = "https://other.domain.com"

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"input[https://anchor-origin.domain.com] and resolved[https://other.domain.com] anchor origins don't match")
	})

	t.Run("error - different canonical ID", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = updateCommitment
		md[document.AnchorOriginProperty] = anchorOriginDomain

		docMD := make(document.Metadata)
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "other-canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"input[canonical-id] and resolved[other-canonical-id] canonical IDs don't match")
	})

	t.Run("error - different deactivate flag", func(t *testing.T) {
		md := make(map[string]interface{})
		md[document.RecoveryCommitmentProperty] = recoveryCommitment
		md[document.UpdateCommitmentProperty] = updateCommitment
		md[document.AnchorOriginProperty] = anchorOriginDomain

		docMD := make(document.Metadata)
		docMD[document.DeactivatedProperty] = true
		docMD[document.MethodProperty] = md
		docMD[document.CanonicalIDProperty] = "canonical-id"

		err := equalMetadata(docMetadata, docMD)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"input[false] and resolved[true] deactivate flags don't match")
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
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
          "protocolVersion": 0,
          "transactionTime": 1635519155,
          "type": "create"
        }
      ],
      "updateCommitment": "EiDOeUN2rx3T9-48s-3qrv6bObQqEjJU9mQZOfJ3E3rMEg"
    }
  }
}`

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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InNlY29uZEtleSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJQLTI1NksiLCJrdHkiOiJFQyIsIngiOiJQVXltSXFkdEZfcXhhQXFQQUJTdy1DLW93VDFLWVlRYnNNS0ZNLUw5ZkpBIiwieSI6Im5NODRqREhDTU9UR1RoX1pkSHE0ZEJCZG80WjVQa0VPVzlqQTh6OElzR2MifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iXSwidHlwZSI6Ikpzb25XZWJLZXkyMDIwIn1dfV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJVeFlMclZVY1VNa21vZnVxMlhIbnBYbTlEeW9ZMTJmUXBGaldCQllTWEhBIn0sImRpZFN1ZmZpeCI6IkVpQnVHTDI5RUhlZW5XNzE3MmlHa2liXzlkSUtyQXpLN2phemdFUWpoRkNSa1EiLCJyZXZlYWxWYWx1ZSI6IkVpQ1lzVjdfdDJyLUk1Yktlemt5azUwYWJiN0I1SGprdGpWdkZzMnNqaDJ0UmciLCJzaWduZWREYXRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKaGJtTm9iM0pHY205dElqb3hOak0xTlRFNU1UWTNMQ0poYm1Ob2IzSlZiblJwYkNJNk1UWXpOVFV4T1RRMk55d2laR1ZzZEdGSVlYTm9Jam9pUldsRFJIZzBTMFUzYkRaMGEyMTJVaTFPT0VST2RqUlVlbkoyYkZoM1JubGFaREkzZDFGR1dFUjRhMDExWnlJc0luVndaR0YwWlV0bGVTSTZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SW1WbFRrdDFablZtUzFkUk0xSjNkbWxFTlRBdE5uUkhOMDVDVm5WdU9YZG5aVjlVTlUxM1kybDJSbU1pTENKNUlqb2lPVFJhVDA0M01WVkZURGhmVmpjNFJtSnlZVEJ1UldST1ZGRkxhVmxxTmpFMlFXdzRlV2RyT1VNMlJTSjlmUS5pOGNCSGlZSGhsVkkzc3laQ0R0eWk2MktJTTR0Z3Vkby15eWNWaktNNTlhWHYtRTNGU1JnNlFjTUNuem5aMHhBVm9vZ2NzOGRvRVpQOUdmSmd1OFlxZyIsInR5cGUiOiJ1cGRhdGUifQ==",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InRoaXJkS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQV9zVXJjbWcxY0dfNkpmT2traF9fanZBMzNwNFZRSXNEUUxUOXJReVp2MGcifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlEVEJfNlNPall3YXUyRS1TRm5kRk1uU1U1d2lzd3B6Q3o5c1BpckhreEdfdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRneExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFE0TVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xETFZWYVRtcHlSbmh3Wm05SWFIaEdTMmhDU1ZOR2JYWjBVazFrWmt4UU9WaEtiMUJsTm5kWmIybFVRU0lzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJbk5UUnpkdWRrTlVSRFV0ZFdsMmRqQktORXRoUzNCWFJ6Z3hhbGc0WlRNM09ESktibUpMYTA4NFFWa2lMQ0o1SWpvaVZ6Wm9RUzFOZHpCMldYTnNaRUZvUm5walpsUXpXSGszY1VWdU5WTlFka2gyVm5ScE5HNXZNMDFvTkNKOWZRLl84TWtLbDZXMjNncDFZaEJ0LTNVZjRESnNLV0NLR0V1dzhEUFJLd3pxTDVtM0dScWlJOGtQVWFCTHM5T25ocjVYRlV6MFdVV25YallSemhfX2JTcnJRIiwidHlwZSI6InVwZGF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtc2VydmljZXMiLCJzZXJ2aWNlcyI6W3siaWQiOiJkaWRjb21tIiwicHJpb3JpdHkiOjAsInJlY2lwaWVudEtleXMiOlsiSkRFQnl4WjRyODZQNTIzUzNKRUpwWU1CNUdTNnFmZUYySkRhZkphdnZoZ3kiXSwicm91dGluZ0tleXMiOlsiMmhSTk1Zb1BVRllxZjZXdTh2dHpXUmlzb3p0VG5Eb3BjcGk2MThkcEQxYzgiXSwic2VydmljZUVuZHBvaW50IjoiaHR0cHM6Ly9odWIuZXhhbXBsZS5jb20vLmlkZW50aXR5L2RpZDpleGFtcGxlOjAxMjM0NTY3ODlhYmNkZWYvIiwidHlwZSI6ImRpZC1jb21tdW5pY2F0aW9uIn1dfSx7ImFjdGlvbiI6ImFkZC1wdWJsaWMta2V5cyIsInB1YmxpY0tleXMiOlt7ImlkIjoiY3JlYXRlS2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4Ijoic1YwTXlXUTFaMDNkTEV5Vk9NZmZRenAzWjI1YlFfaGR6ZTdBbTloaGdGQSIsInkiOiJtZUF1Nk9sb1lBdnVwZEFlaFBjT0ZCYVJNXzROSFUwR2FuRTNQOWJwMVJrIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJhdXRoIiwicHVibGljS2V5SndrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiTThFd0p6MHpibFNZSDFhMWVmMFVVcnhBN1Jkb3hsb1BLUFU1Y1lzYWIxbyIsInkiOiIifSwicHVycG9zZXMiOlsiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCJ9XX1dLCJ1cGRhdGVDb21taXRtZW50IjoiRWlET2VVTjJyeDNUOS00OHMtM3FydjZiT2JRcUVqSlU5bVFaT2ZKM0Uzck1FZyJ9LCJzdWZmaXhEYXRhIjp7ImFuY2hvck9yaWdpbiI6Imh0dHBzOi8vb3JiLmRvbWFpbjEuY29tIiwiZGVsdGFIYXNoIjoiRWlCZ1VTeHE4Mkd4eFpLaHFkMXpqSWdCdDh2WkxYZHdRdUJrSDBVM05vZTBOZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQlh4bEJaNHhzaXNZNVh0QkJ0QzMyYnhueTVzUGx3QXNRb3RDV245bUlwRncifSwidHlwZSI6ImNyZWF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImZpcnN0S2V5IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2SyIsImt0eSI6IkVDIiwieCI6IlBVeW1JcWR0Rl9xeGFBcVBBQlN3LUMtb3dUMUtZWVFic01LRk0tTDlmSkEiLCJ5Ijoibk04NGpESENNT1RHVGhfWmRIcTRkQkJkbzRaNVBrRU9XOWpBOHo4SXNHYyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRDZuaVZrMm9xQ251OHMyZFBYWFhVWGhfclFDX2JLdEZKY2JMXzNIdjdmRlEifSwiZGlkU3VmZml4IjoiRWlCdUdMMjlFSGVlblc3MTcyaUdraWJfOWRJS3JBeks3amF6Z0VRamhGQ1JrUSIsInJldmVhbFZhbHVlIjoiRWlCLU1lMWM0MzJRaExmOGFHRVBfLS1qSDlKNjdHSlFhb1NZeFdMN2Nla0JBdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlKOS5leUpoYm1Ob2IzSkdjbTl0SWpveE5qTTFOVEU1TVRZeExDSmhibU5vYjNKVmJuUnBiQ0k2TVRZek5UVXhPVFEyTVN3aVpHVnNkR0ZJWVhOb0lqb2lSV2xCTUV0cE9XOTFkbEpDV0RnNFJ6bDJOMFl6UWxoeFNUZHBZMGxXZW5ObVRqQk1RMTlvVlRCSk9YRk5keUlzSW5Wd1pHRjBaVXRsZVNJNmV5SmpjbllpT2lKUUxUSTFOaUlzSW10MGVTSTZJa1ZESWl3aWVDSTZJa1F5ZEZsbGIwUTNZbGRXUVVGb1RqWlNSbXhCUnpoYUxTMXhVRFp0UmpCVU0wOVNhemRLYVVaTlFWVWlMQ0o1SWpvaWNFcDBNM0ZMY3pKT2NXOUJjMkZxVG5wS2NHOTNaa2R4VlVablNYaDRkV1pUVlZseldqaDZNVGhZYXlKOWZRLmFOb2RvWDVENEpTbWtyb3ZpM0FPMUFidEkxM0RDZnJpSktkRW1WVDFoVjcwY2FtcW92YktPQjlFa21YMFRPRC1CUzlTQk5Mck84eHdmc2p4X1c5alBBIiwidHlwZSI6InVwZGF0ZSJ9",
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
     "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InNlY29uZEtleSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJQLTI1NksiLCJrdHkiOiJFQyIsIngiOiJQVXltSXFkdEZfcXhhQXFQQUJTdy1DLW93VDFLWVlRYnNNS0ZNLUw5ZkpBIiwieSI6Im5NODRqREhDTU9UR1RoX1pkSHE0ZEJCZG80WjVQa0VPVzlqQTh6OElzR2MifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iXSwidHlwZSI6Ikpzb25XZWJLZXkyMDIwIn1dfV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUJVeFlMclZVY1VNa21vZnVxMlhIbnBYbTlEeW9ZMTJmUXBGaldCQllTWEhBIn0sImRpZFN1ZmZpeCI6IkVpQnVHTDI5RUhlZW5XNzE3MmlHa2liXzlkSUtyQXpLN2phemdFUWpoRkNSa1EiLCJyZXZlYWxWYWx1ZSI6IkVpQ1lzVjdfdDJyLUk1Yktlemt5azUwYWJiN0I1SGprdGpWdkZzMnNqaDJ0UmciLCJzaWduZWREYXRhIjoiZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKaGJtTm9iM0pHY205dElqb3hOak0xTlRFNU1UWTNMQ0poYm1Ob2IzSlZiblJwYkNJNk1UWXpOVFV4T1RRMk55d2laR1ZzZEdGSVlYTm9Jam9pUldsRFJIZzBTMFUzYkRaMGEyMTJVaTFPT0VST2RqUlVlbkoyYkZoM1JubGFaREkzZDFGR1dFUjRhMDExWnlJc0luVndaR0YwWlV0bGVTSTZleUpqY25ZaU9pSlFMVEkxTmlJc0ltdDBlU0k2SWtWRElpd2llQ0k2SW1WbFRrdDFablZtUzFkUk0xSjNkbWxFTlRBdE5uUkhOMDVDVm5WdU9YZG5aVjlVTlUxM1kybDJSbU1pTENKNUlqb2lPVFJhVDA0M01WVkZURGhmVmpjNFJtSnlZVEJ1UldST1ZGRkxhVmxxTmpFMlFXdzRlV2RyT1VNMlJTSjlmUS5pOGNCSGlZSGhsVkkzc3laQ0R0eWk2MktJTTR0Z3Vkby15eWNWaktNNTlhWHYtRTNGU1JnNlFjTUNuem5aMHhBVm9vZ2NzOGRvRVpQOUdmSmd1OFlxZyIsInR5cGUiOiJ1cGRhdGUifQ==",
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

const deactivatedRR = `
{
  "@context": "https://w3id.org/did-resolution/v1",
  "didDocument": {
    "@context": [
      "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:orb:https:orb-4.stg.verify.interac-id.ca:uAAA:EiCIpxT2PenEKW3F2aczmdUWhQEGZzjvY154tf20x7yT4A"
  },
  "didDocumentMetadata": {
    "canonicalId": "did:orb:uEiCFp1MK-2sPKmgdQ4BIinrP4WcHV4u-Amb6Zj5jy6Q7cQ:EiCIpxT2PenEKW3F2aczmdUWhQEGZzjvY154tf20x7yT4A",
    "created": "2022-11-25T14:25:37Z",
    "deactivated": true,
    "equivalentId": [
      "did:orb:uEiCFp1MK-2sPKmgdQ4BIinrP4WcHV4u-Amb6Zj5jy6Q7cQ:EiCIpxT2PenEKW3F2aczmdUWhQEGZzjvY154tf20x7yT4A",
      "did:orb:hl:uEiCFp1MK-2sPKmgdQ4BIinrP4WcHV4u-Amb6Zj5jy6Q7cQ:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQ0ZwMU1LLTJzUEttZ2RRNEJJaW5yUDRXY0hWNHUtQW1iNlpqNWp5NlE3Y1E:EiCIpxT2PenEKW3F2aczmdUWhQEGZzjvY154tf20x7yT4A"
    ],
    "method": {
      "anchorOrigin": "https://orb-4.stg.verify.interac-id.ca",
      "published": true,
      "publishedOperations": [
        {
          "type": "create",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6IlFrSmRleUxrSU51SkdidWotX3E0NDM4WEhXMnA1dVZKTDF0OVd5N0RaM28iLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJRa0pkZXlMa0lOdUpHYnVqLV9xNDQzOFhIVzJwNXVWSkwxdDlXeTdEWjNvIiwia3R5IjoiRUMiLCJ4IjoiMHBlODJZWktPRzFvdjRCZmpDWk1Ba0hJWGp5X3U3dXVnZ2YteXZheFRiTSIsInkiOiJqZXpld3A0UVB6RFNOZWFieF9MNTZEVkhySlZJYjVwY0Q4SXREZ19SRWhJIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiI3OXNGdERiUFZUOGFOWXZ2U09EWVkydHRCYWRidVJtcEpqbFlaNWZZbmZzIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiNzlzRnREYlBWVDhhTll2dlNPRFlZMnR0QmFkYnVSbXBKamxZWjVmWW5mcyIsImt0eSI6IkVDIiwieCI6Il95Z2RSODdxNW1DOXpwZUNiYmd6cVlndFNYWXJ0TGhnS3gzOW1iak9zZHMiLCJ5Ijoic1E0WXlieVY1STVsM2VTNTNVQzVpUzVtYWZ1NFRRWUJlbHJKWkhSWC1zOCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpRHVuVFNjdl9GNWZZcE0tWWNneFBtNUdTa1o0c0RMSG5RbG10V1VCSVpPSHcifSwic3VmZml4RGF0YSI6eyJhbmNob3JPcmlnaW4iOiJodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYSIsImRlbHRhSGFzaCI6IkVpQm9BUno0eDdpXzVRM3gtWVdVRkhVOFppS19CdERzbXVkazZZVGtfem1LZ3ciLCJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaUN0cFhGbWszbnlXc1NmVVlGZU9wbnBuLVJreE95R2hUNUNiNGVqSHRkZ2NRIn0sInR5cGUiOiJjcmVhdGUifQ==",
          "transactionTime": 1669386337,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiCFp1MK-2sPKmgdQ4BIinrP4WcHV4u-Amb6Zj5jy6Q7cQ",
          "equivalentReferences": [
            "hl:uEiCFp1MK-2sPKmgdQ4BIinrP4WcHV4u-Amb6Zj5jy6Q7cQ:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQ0ZwMU1LLTJzUEttZ2RRNEJJaW5yUDRXY0hWNHUtQW1iNlpqNWp5NlE3Y1E"
          ],
          "anchorOrigin": "https://orb-4.stg.verify.interac-id.ca"
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6Ik1mV3V5bVhQRlV0eFVJM1VOSFpianF6MlVjbndtX0cyVHZ4VHRjV2hfd00iLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJNZld1eW1YUEZVdHhVSTNVTkhaYmpxejJVY253bV9HMlR2eFR0Y1doX3dNIiwia3R5IjoiRUMiLCJ4IjoiN1JSNEN0LXAxWlZYYnVQQ1RESTVDVktxc3lqNXFqODdEdzVBODdGdEhxYyIsInkiOiIySXMzaGFMV0VJTEVDM1hZUFNKb3plZ3MzU0JJNkFmc2hoUkJPeG1fZVdBIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJuYndybWFNaFJZUU9iWkk4alM3MXhYMnJmQTkyZXdIcUxxVFVhd1RXai1NIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoibmJ3cm1hTWhSWVFPYlpJOGpTNzF4WDJyZkE5MmV3SHFMcVRVYXdUV2otTSIsImt0eSI6IkVDIiwieCI6IkRIN19FSGxqMGY0UmF4NnZ3Tml5dTVjSUhkeWdBMU9ad1FScFFqMFQ2ZmsiLCJ5IjoiNlk2TXpzVmtOOURXQ3k5VmI5MEJnNlVzTDN2U2NfYjBjX0lTeDJTY25zSSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQjdxdTJnY0g3eEtQa1JLc1BtTHNfZVVpV2x1WjNmdEd1WXJBazVCbDFGZXcifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlCcTBXZWJCaGowaFYwS3ZXb3hFOWZUWEhmTHU5NFJkV05mWE9fZWwzNTlEZyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVRkJTRXhYUTBaUlVsSnRkbUZNYUdOa1RsQXphazR3TVhGR1lYbGxUbE50TFZnd1RXaFVVa040YUdWQklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVNIQTRMVXRSWldGQ05qWTJNazQ1Vm5JMFIweHFRelZLTTBoVmNFSTJRazFOYTJNd0xYUk1WMjlpTUNJc0lua2lPaUp6UkhjMFVVUnhiRXR0VlhsQ1dFWnZVVmgyU0hocGEzbEZZbTVSV2pjMUxXRTRlalJNYVVkTFozVkpJbjE5Lmd4MzcxOFU1YXlPR2hGN0VEZC1kLWNWZHQwNENLREFISGlydUZMQWQzbzF2ODNVUFplVEp5Y3N5RkNEdGhQZ0p1Q1J3ZmhvNjRrV0NpVERmNU5rODRBIiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669386457,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiCBVaDPY8KfmuFlZeK833ZwFxmez32xYlcaote8F_zENA",
          "equivalentReferences": [
            "hl:uEiCBVaDPY8KfmuFlZeK833ZwFxmez32xYlcaote8F_zENA:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQ0JWYURQWThLZm11RmxaZUs4MzNad0Z4bWV6MzJ4WWxjYW90ZThGX3pFTkE"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6IjlONWxPTFd5clo3R284amZhY2tyQVZXWXZEOXZVRFdMY25yX3RIdW8tY2ciLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiI5TjVsT0xXeXJaN0dvOGpmYWNrckFWV1l2RDl2VURXTGNucl90SHVvLWNnIiwia3R5IjoiRUMiLCJ4IjoiUWNMLTZNUTBrMWpHUkdkVWYtT1lZRG9uSG9LZ01QQWZfdTFtejN4U1BoRSIsInkiOiJOZjkxRWduSzl5UEl5cXR6Q1FMbWNXal9yUzBzOG0tSUJiekRPTTNIbURBIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiI2emdJckJnd2o2cmZIWDMySXp4dlFJTEZQYTNqSWJYUFNCRkl1ZmR6RnI4IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiNnpnSXJCZ3dqNnJmSFgzMkl6eHZRSUxGUGEzakliWFBTQkZJdWZkekZyOCIsImt0eSI6IkVDIiwieCI6IkNkVWJBV3dmdlpvWl9xZW1QelhOaVVFT3hrNHpaUU5ZRGRnWWhSYTk0b2ciLCJ5IjoiLTQ2TFowRVZBTjNIR3hHS1pRcjV6UjhfdElITjV0Ump5a0tnamljdmJKQSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQm9uWG1XS09LZUJPMVZTZDREWXhxNnR5dUthNWNwS2J6enhtd1lOanFtS0EifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlDaWVPMnlrOEs3dGRZRzVNaVlwelB2b2hKLUJicDNWbElrX3V4a1hJU2x5dyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVTmtURkJ3Y1Y5YU9YUllibWMzY214alpHeFllREV3YlhaSE5FeEpZWGcwU1hScE1FaFJXR3hUVG1abklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVltbG9aMms0Y0hoM016YzBlWGRIYVdsRVgyWkpTME5oZVdSdFZHZzNkemR6TTB0a2J6TjFOazU1TUNJc0lua2lPaUkyUW5ORlJFaE1ZbEU0Wm1sd2JVTmxablZzWldsM1MyNW5aVWRKWjNvMVZVMVZRbTlMUW5CMk1IRk5JbjE5LlhUNFc2WWdoMVN5NFlFRF9vRDdXWHZ0VjJmSEdPOVh5UW84RXpQQmxtcllvQXM4dTVIQTJfTjdNRW90WDd1T0tfVlpLd2w1UXZCWVI1RWxYRndQTll3IiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669388377,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiBM4W_V5WaLDMozWeDVMhdcid8lVe9F2ByALvvTLXfCUw",
          "equivalentReferences": [
            "hl:uEiBM4W_V5WaLDMozWeDVMhdcid8lVe9F2ByALvvTLXfCUw:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQk00V19WNVdhTERNb3pXZURWTWhkY2lkOGxWZTlGMkJ5QUx2dlRMWGZDVXc"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6IkcxUTg5ZTg5MWZSME1pa2pIckdUVUJZeGdGR1BMcktMSHpJRXJKRXo0ZUEiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJHMVE4OWU4OTFmUjBNaWtqSHJHVFVCWXhnRkdQTHJLTEh6SUVySkV6NGVBIiwia3R5IjoiRUMiLCJ4IjoiY3pOZGpGVUtDTnVzNFFjeHFKdWVwQmJYa3BOZnJrMkVaVFB1eGtiSUZ5byIsInkiOiJaSjBZNjA2UjBjb0RIM25vTUg3cmU0Qkk2Sld2dnlmLXd0Mkc5ZzFBUXpjIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJiUzhwQVV2V3RncmxyLUdpNURFRE9YR3d6ZkVyX0ZMWU1tZW9mSHMzYjlRIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiYlM4cEFVdld0Z3Jsci1HaTVERURPWEd3emZFcl9GTFlNbWVvZkhzM2I5USIsImt0eSI6IkVDIiwieCI6IlI4SkZQN3VmR2xpdE8tb0RuOVRPdEpGNFo3TUFXbVIzdDdGNEQ5OVY2b00iLCJ5IjoidklETEhtN2VteUQ0VllkUlUzWXFmY194WFBzZVFLeTJZSTBHcmg4MHlZTSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQWEzU0hOWVV3N2J2NnB6cVhUS1JQSWVvRlBYam9QUl9xalNTekFwb19hbFEifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlBQ2FnT3NKa0kyZ2dfS1NCWXllX1dHamhaUjlGU0xuQXZqTnFUa3g2V2hVUSIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVRlZTMjUxVTNOUVdqUkxSazFEUkdKMFoySjRkM2hSY1VWalNFbElSVXhwU2xWMU4xUXhNakpNV21WUklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVpYUkZTMkZLUW1WWldsQkJNWGN4VW1GS1FUQXRRV2sxT1RGb1ZEYzJPSGhQWmsxclZYUnVVR2hVZHlJc0lua2lPaUpYYzNKM1IzcHhka2h4VVVKV09WbzJXRFJYYmpRMlVYSjVVMnhVVkZkaGMwWjBhRVJtUzFOcWVFUk5JbjE5LjI0RWpVUFhNVTRMT2dkejItNzZMcHAwdHN0STdoRFVENjgwLVFCc1NvTzU3RnlNR2ZEU1dhTjdMMDI4Y25qaC1GUVpodWxyYlJwYmlscUc1SGZhTFZ3IiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669633657,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiD6ZlcebBL5ERyCWzQKW6iNxdRSOH1lCeWcOVu_kixbyA",
          "equivalentReferences": [
            "hl:uEiD6ZlcebBL5ERyCWzQKW6iNxdRSOH1lCeWcOVu_kixbyA:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpRDZabGNlYkJMNUVSeUNXelFLVzZpTnhkUlNPSDFsQ2VXY09WdV9raXhieUE"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImVpWkZ1T01zSE5YTmFKWXRjZnVoWjVhN2NOaUZqdVdWODVINXhzN3RVTlUiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJlaVpGdU9Nc0hOWE5hSll0Y2Z1aFo1YTdjTmlGanVXVjg1SDV4czd0VU5VIiwia3R5IjoiRUMiLCJ4IjoiNUdNYmZxUTZCLS1OVVJzVnVjQm9HY25OaUJjUWhGa29Od21QOGdocDZITSIsInkiOiJ4UFFmb0lKWTgtdkhlSzNqT3RyNkF5YzgtRXIxTVFKeUV0ZVUxazdlTlBRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJsZHBfZ0MwdXJlZnFFbVp5VWY1UHlocEhMQnRNbnp3dVowUFpBYjNtR1BJIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoibGRwX2dDMHVyZWZxRW1aeVVmNVB5aHBITEJ0TW56d3VaMFBaQWIzbUdQSSIsImt0eSI6IkVDIiwieCI6ImNuVzVMWnczdExFRTV1OUhPNWt4Z1VqcHZLRS1DVHpCQldmV3p0TmFpTmciLCJ5IjoiVk82RncycnpNWVBmcFBSRlU0b28wMXJ2N0V4ZTNqV204aWFMS1VtX0g3OCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQ3U1SDZuZDZEZ3NBb3d4eFBBOTRXZ0pES3h0TjJQZ19nV1RkSFNMSUhndFEifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlESEpIS2YwNVZVT3ptZFJUcDNRT2V5b25vaEtzSVZzRERURzZZdmlvNDFzQSIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVRmxPV1ZRTlVGaU4zQkZPRlpCUW5wVFpuSnZZbmN5Ylc4emJVcG9iWEYwUzFCc1JFMVJTVVJ5ZVZGbklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaVVUZ3lRbEF3YjI1MVZFdE9WalZZYWxoNU1UbHVNamx3VlhoR1kwRXlVbk4wVnpFelJuSllSVk5WUVNJc0lua2lPaUpuVXpFNVUwRnpNMFUwV0ROblkzbDJkblpKTW1OTlJrbzBla2h1VUV0d1NYcHlXbEZ5V21FeFNrWm5JbjE5Lmd0VjZDMlVUa1BBNkRvMzdyc1ZHR3FuQ05NQ2lyV0Y1M09mcTRaNGptOFVBQjl1cHhhT0RmTDRodnRERlc5bE0yc2VLUkZzTWNtd0ZUWW11TFZXSFN3IiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669634890,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiC42n_UQS3lDmSCIOuDa0zWFr4gv_2_NqcQZVlHRjMoog",
          "equivalentReferences": [
            "hl:uEiC42n_UQS3lDmSCIOuDa0zWFr4gv_2_NqcQZVlHRjMoog:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQzQybl9VUVMzbERtU0NJT3VEYTB6V0ZyNGd2XzJfTnFjUVpWbEhSak1vb2c"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6ImdDTFc1WUNKazVOdW9icVRYVGNzQUdhNWJhcHpERl95RzNYbzhvc01BQzgiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJnQ0xXNVlDSms1TnVvYnFUWFRjc0FHYTViYXB6REZfeUczWG84b3NNQUM4Iiwia3R5IjoiRUMiLCJ4IjoiT241Zl8wcFdrSUtHQzMxcE1PR21DS1BudDU0dUdWbktZWGNqZHpZaGw4NCIsInkiOiJwQks0MFY5NGtDdFBFcmZTYTNvYnlpai1CRTJtR2oxdTItLUozaF9HRUdRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJsbTZ4b1JsV2llRTZmZ293SUh1ZERNMkhUX0E0bUxKUlozRTdSRFdvbF9nIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoibG02eG9SbFdpZUU2Zmdvd0lIdWRETTJIVF9BNG1MSlJaM0U3UkRXb2xfZyIsImt0eSI6IkVDIiwieCI6IlNZcjMxSnZNTnlteDRmX0sySnllb0NwcVU0YkpzNjZBWUw5NkpvLTRSdDAiLCJ5IjoiNzcxam9sMHBPcV9GVXpRenRNMDRtUF9IQlc2aHloZy1acW42UHNubC04ZyJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQnpJS2QtNnpCNjBCbFlWbVJYd29vZ1V1YVB1cTJhbFltZXUxeE9sRTZFeHcifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlBSU9HR2F5QzJWNDlobWJUNnRyZ2l5Um5USWdRN25QdlBHcUdQZzhnd3JSUSIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVSk9WRTlwTFhOdVlqTXdNSEJ4Tm5KQk9ETjRVM1F4VDNoV1NHdFlSbUZJTm1aT1pUbHpYMHAxZEZsM0lpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaWFuRnhWbVpCWW1NNVIycE1hVFpTUlZseVRuVTNhWGhZTFdSaU4xbHNPRlV6TUc5TVJsbGxZMFpzYXlJc0lua2lPaUpCYjA5d2VVdGpORmhUVFZaaVlrZE5hakl5V1RONGJVcHdSbXQ1Ym5GdGVYZzFSWEJyV2taWE5HYzBJbjE5LnQzYUQzOW5PczR2elRrcDRSSFE5NElrTC14SmpENjJ1Q3Rzel9yeWRMS2dOaFdKTmw4dHhRVzBaTEJsWkJhWkhidFZzdHYza3pNdjJrR1hWN0RHZ3dRIiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669635070,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiCpH0vIDXRYLtyLwrmIulP0PfYh2UHN5n9iSdgZ1TwdOQ",
          "equivalentReferences": [
            "hl:uEiCpH0vIDXRYLtyLwrmIulP0PfYh2UHN5n9iSdgZ1TwdOQ:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQ3BIMHZJRFhSWUx0eUx3cm1JdWxQMFBmWWgyVUhONW45aVNkZ1oxVHdkT1E"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6InZfZDVISGJCODdkbXAyRnMzRVFXbXpLUHZkSEVMUW12eHMxaFNDNFlxQkEiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJ2X2Q1SEhiQjg3ZG1wMkZzM0VRV216S1B2ZEhFTFFtdnhzMWhTQzRZcUJBIiwia3R5IjoiRUMiLCJ4IjoiQ2hrVGlXVC1XVGd0TUtoajJPR0hwckNKTnlHVXJHRm9ma1d1R1lpOEpjYyIsInkiOiJzTmhDWlFXeFBuN09QUlB0TU9KeGlkeWlqQ00zUVVKOWhtLXZ5cHJPQ19vIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJoT2RrT1ZvUDYtUXZET1JSanhsUWoxelJkRkdWWU1tYWJCNjlHdDNuUzUwIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiaE9ka09Wb1A2LVF2RE9SUmp4bFFqMXpSZEZHVllNbWFiQjY5R3QzblM1MCIsImt0eSI6IkVDIiwieCI6ImhXX18xWHVSeVl2NzZNcUl2S1EtN2xpMjlKMW5UM1ZrcUFuVGlqTHZwRmciLCJ5IjoiZTUtUzBOMjVlV19iTWV0Wl9ndVNRaWJITE1fQjQ1aWJ2anBDSlFtUVBKVSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQm9DcVEyQ1Y4OEJvLTdTclppUnpuSDBzYTdtM2Ywek1SQWNwbHZ5aGhZSXcifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlEZGNvVzhoTVd2VXdyb21DZEl5aGh0dGRlTzNKWEN5MmVWTXZFWEkyRkEtdyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVUmxOMUZMT0ZkU1dtSTVWV1UzZUZCaVdXcEhSVXhMTkdkMU5WRnlPRVkwY0dGZlEyMHhUbHBGYjBSM0lpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaWJERnFkMjVrVEdFME4xWkRWRjh3VDNoNk5UbG5NWHBYV2pkVWREQlNkbTVYYmw5SVZXRXhiR2hCV1NJc0lua2lPaUpGZEVnMFNsRmlNVXhGV2tjdFFsaHVUVEkyY0d4aGRERnFVVmxMWm10Uk5GOVhSRE5EVkVoSWJWbFJJbjE5LnBEQmJhOVpBbkI4Rm9qWXpZMEJXZ0JGOUhNY2NYZkExVmtyZ29rdURKZW1oLThRSFRLWVlYbUNwLUpKOXFIWmlpT1Z5dnlPak10dklsYUE1c0czUHlRIiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669636537,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiAeHplEAakTPWrMr7uZpGEARKO3Vya-5Tg0lUgfxITI0w",
          "equivalentReferences": [
            "hl:uEiAeHplEAakTPWrMr7uZpGEARKO3Vya-5Tg0lUgfxITI0w:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQWVIcGxFQWFrVFBXck1yN3VacEdFQVJLTzNWeWEtNVRnMGxVZ2Z4SVRJMHc"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6IkcteUNQeXBOaUJyb21BeC1NNml2dlRzdjV5anJJT1pmbUcyXzdINE5vTnMiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJHLXlDUHlwTmlCcm9tQXgtTTZpdnZUc3Y1eWpySU9aZm1HMl83SDROb05zIiwia3R5IjoiRUMiLCJ4IjoiTHRQWjRqMFhCT0xhYTRoSjY4MGp5YXluSEltM3kxYVpMWDJVdy1zVzVaMCIsInkiOiIyVjI3VzlIMndfUW1IY2laaURUOFlUQ1lxNUl3LXc0SlViZm1xWFNseFFZIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiJGZmdxS0RtWUNCWHNVZTVLNkREN1NlU2RlaXZMN0J3QXp5S0htbDN1VGtJIiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiRmZncUtEbVlDQlhzVWU1SzZERDdTZVNkZWl2TDdCd0F6eUtIbWwzdVRrSSIsImt0eSI6IkVDIiwieCI6IjNzSE14cFZ2TXNrbXdSdUdJbVJoWHJFeVM0VzF4TjZVWkRUQXpiSXE3dDAiLCJ5IjoiRFJQb3Y2R09MMVlKU19COFNWVk1vVWc3Y2w0bnc2TGNqWklGYzYzTXdKUSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQXB1Zjc3RDhGdEttQVVialdUTnF4YlJoNlRqaG42ZnZoWnROV21DNk9nZUEifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlCUzNzcUZJRUExeTNZS0EtWXp0bDZpWmZZLWRBa1JfOXVwVFhJaEg0NExRZyIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVTmtRVnBaT1ZGRmVXSXdhMk13VlZsR01FOTBWVmxXWldweGFrNVhWRjlGVFZaWVVFbHFRMWRZWkhSUklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaU5UZGxOa0p5TjIwMVpYZG9SVXhUYzA5c1QweG5Ra2szY1hKcFFuY3hlbFZuTFhBMVdGTlhOMVZET0NJc0lua2lPaUpoTkZGTVRXOXJhVlJWZEVwRldFZEhaREZ2WVRrM2NuTmliUzEyWVhCblJ5MXhia1Z0VTFCcFpHSlpJbjE5Lk5lMlBrQ2NWZ2tTRUhoZExpNXpNZlF3bDBsLVlWcE4tWURUdnE1OGhxVGxaRnZFLXpac3llb3YydW9sX2owMmNwZ19WUUVXaTV0d0h3VDg1SnMwMjVRIiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669638157,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiDLeWea534P3_LPE4BpHx0f5-oWOvAQUfo47rraKh4Y3g",
          "equivalentReferences": [
            "hl:uEiDLeWea534P3_LPE4BpHx0f5-oWOvAQUfo47rraKh4Y3g:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpRExlV2VhNTM0UDNfTFBFNEJwSHgwZjUtb1dPdkFRVWZvNDdycmFLaDRZM2c"
          ]
        },
        {
          "type": "update",
          "operation": "eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJhZGQtcHVibGljLWtleXMiLCJwdWJsaWNLZXlzIjpbeyJpZCI6IlhIbEJqMjNjamF3eXJhYWEzcHBidXdScGhfV2JXOXNfelZGR3NFM0FuUVEiLCJwdWJsaWNLZXlKd2siOnsiY3J2IjoiUC0yNTYiLCJraWQiOiJYSGxCajIzY2phd3lyYWFhM3BwYnV3UnBoX1diVzlzX3pWRkdzRTNBblFRIiwia3R5IjoiRUMiLCJ4IjoiV0NIZV9RWHFfMHRKZ2ZMZjJfMWZjVjJPZXhQMHF6Z0hWUFpkdkRDQ2p5byIsInkiOiItQVRTcnpGS2pNQ0xNb2NqdG5EeXZnY0NGVEFOTDNyN3YxTkhXR19sOWZRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIl0sInR5cGUiOiJKc29uV2ViS2V5MjAyMCJ9LHsiaWQiOiI5QnFqang4elZlWkszek5WX2tjM2sxOXp6VVZXMXU3SjFvd3ZNVFN2SnE0IiwicHVibGljS2V5SndrIjp7ImNydiI6IlAtMjU2Iiwia2lkIjoiOUJxamp4OHpWZVpLM3pOVl9rYzNrMTl6elVWVzF1N0oxb3d2TVRTdkpxNCIsImt0eSI6IkVDIiwieCI6IjlmLVJNUHVyQ0JKcDVGTVJjdzZWR3BJNFB5bGZLM2J0OE9waDI4bUNqVzQiLCJ5IjoiTmFYai1hallrS3JsMGZGRWpNNmRDUTE5UmVHUlB3R0Y2dmw5T1BrNkxLNCJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQUxDdy15S1JDVTRTS0p5T2kzTWpEQW5SS09PU1kwNnNVRGxWZ3JFbWVla1EifSwiZGlkU3VmZml4IjoiRWlDSXB4VDJQZW5FS1czRjJhY3ptZFVXaFFFR1p6anZZMTU0dGYyMHg3eVQ0QSIsInJldmVhbFZhbHVlIjoiRWlDTFNTUGN5QzVUTVlVY2o3Si1tU2ZUN2g1c2ZjMWlqZUZ2ajVjNW5wcnA1USIsInNpZ25lZERhdGEiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1zeEluMC5leUprWld4MFlVaGhjMmdpT2lKRmFVRkJlV2hsWHpVeFdHUXliV0pMTkhvM01VUndPRkJUTjJWeE1WZFRhMEkzZDBwRlptTlFVbXh3WjJGQklpd2lkWEJrWVhSbFMyVjVJanA3SW1OeWRpSTZJbEF0TWpVMklpd2lhM1I1SWpvaVJVTWlMQ0o0SWpvaWFVVldZalZmTUVoUFRrczJWbTV6Vm5wNFgyRkZia0pyYmxSbFdDMVZjMlpPZEZKdFJWWjZjRTExZHlJc0lua2lPaUpyY0dvd2VHWkZSbFF6UzJoWVduUkJjVnBWYUdGb2VFUm9lakJVT0RWM2VHWlNRMmxxVFV0U01YZEZJbjE5LkV5TTExXzRMNTFpTkltamktSTRaWmF6QjFJb0dBWXF0VG5kVnlBZXVOYTRsV0hhVHJjNjhXLXhrX09mYVlxdTQ2N3d3dk5LLVpnMG1pc0tJOFgyb1RBIiwidHlwZSI6InVwZGF0ZSJ9",
          "transactionTime": 1669639417,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiDItz-vNHKvt-FONIXRCESU0rFMNdxjkGZgj_DM8GCCmg",
          "equivalentReferences": [
            "hl:uEiDItz-vNHKvt-FONIXRCESU0rFMNdxjkGZgj_DM8GCCmg:uoQ-BeFpodHRwczovL29yYi00LnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpREl0ei12TkhLdnQtRk9OSVhSQ0VTVTByRk1OZHhqa0daZ2pfRE04R0NDbWc"
          ]
        },
        {
          "type": "deactivate",
          "operation": "eyJkaWRTdWZmaXgiOiJFaUNJcHhUMlBlbkVLVzNGMmFjem1kVVdoUUVHWnpqdlkxNTR0ZjIweDd5VDRBIiwicmV2ZWFsVmFsdWUiOiJFaURTTWRENS1OSG1IaWtpS09mX3pvQXhqVEhmMTI1ZlBTNlptckRrVkxjNDJBIiwic2lnbmVkRGF0YSI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbXN4SW4wLmV5SmthV1JUZFdabWFYZ2lPaUpGYVVOSmNIaFVNbEJsYmtWTFZ6TkdNbUZqZW0xa1ZWZG9VVVZIV25wcWRsa3hOVFIwWmpJd2VEZDVWRFJCSWl3aWNtVmpiM1psY25sTFpYa2lPbnNpWTNKMklqb2lVQzB5TlRZaUxDSnJkSGtpT2lKRlF5SXNJbmdpT2lKd1prRnVjemR2TVMxemFtNUJjazlyUmxFemVsRldSR3RxUTNBM1VGODBhMHBXWW1oUWMzWmtZMUpWSWl3aWVTSTZJamRXY1d4RVJXMU9hSEozTFRKQ1pXeFVTVGgzU0hSb1lreHhhVGx0WDBwRGJGcEZZek01TjBoaFoyTWlmU3dpY21WMlpXRnNWbUZzZFdVaU9pSWlmUS5lOElMTDVvbERON3ZmX3FOSTRaWkhXYzgtTWUyZmxManpoX0lkOWFIU2szbmpFci1VTjYtOFFfWFRwTzRRb3RqaDdXQlpIOVBuYmN3cTZGS3YyMDJHZyIsInR5cGUiOiJkZWFjdGl2YXRlIn0=",
          "transactionTime": 1669639897,
          "transactionNumber": 0,
          "protocolVersion": 0,
          "canonicalReference": "uEiAfg6MnGJWxNwLPlRP8FTnpWzWtJbTwi_VxLsPQFHCjOg",
          "equivalentReferences": [
            "hl:uEiAfg6MnGJWxNwLPlRP8FTnpWzWtJbTwi_VxLsPQFHCjOg:uoQ-BeFpodHRwczovL29yYi0xLnN0Zy52ZXJpZnkuaW50ZXJhYy1pZC5jYS9jYXMvdUVpQWZnNk1uR0pXeE53TFBsUlA4RlRucFd6V3RKYlR3aV9WeExzUFFGSENqT2c"
          ]
        }
      ]
    },
    "updated": "2022-11-28T12:51:37Z",
    "versionId": "uEiAfg6MnGJWxNwLPlRP8FTnpWzWtJbTwi_VxLsPQFHCjOg"
  }
}`
