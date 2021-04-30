/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package loader

const (
	// AnchorContextURIV1 is anchor credential context URI.
	AnchorContextURIV1 = "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"

	// JwsContextURIV1 is jws context.
	JwsContextURIV1 = "https://w3id.org/jws/v1"
)

// AnchorContextV1 is anchor context.
const AnchorContextV1 = `
{
    "@context": {
        "@version": 1.1,
        "@protected": true,

        "AnchorCredential": {
            "@id": "https://trustbloc.dev/ns/orb#AnchorCredential",
            "@context": {
                "@version": 1.1,
                "@protected": true,

                "id": "@id",
                "type": "@type"
            }
        },
        "Anchor": {
            "@id": "https://trustbloc.dev/ns/orb#Anchor",
            "@context": {
                "@version": 1.1,
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "orb": "https://trustbloc.dev/ns/orb#",
        
                "coreIndex": "orb:coreIndex",
                "operationCount": "orb:operationCount",
                "namespace": "orb:namespace",
                "previousAnchors": "orb:previousAnchors",
                "version": "orb:version"
            }
        },
        "AnchorCredentialReference": {
            "@id": "https://trustbloc.dev/ns/orb#AnchorCredentialReference",
            "@context": {
                "@version": 1.1,
                "@protected": true,

                "id": "@id",
                "type": "@type"
            }
        },
        "ContentAddressedStorage": {
            "@id": "https://trustbloc.dev/ns/orb#ContentAddressedStorage",
            "@context": {
                "@version": 1.1,
                "@protected": true,

                "id": "@id",
                "type": "@type",

                "orb": "https://trustbloc.dev/ns/orb#",
        
                "cid": "orb:contentIdentifier"
            }
        }
    }
}`

// JwsContextV1 is jws context content.
const JwsContextV1 = `
{
  "@context": {
    "privateKeyJwk": "https://w3id.org/security#privateKeyJwk",
    "JsonWebKey2020": {
      "@id": "https://w3id.org/security#JsonWebKey2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "publicKeyJwk": "https://w3id.org/security#publicKeyJwk"
      }
    },
    "JsonWebSignature2020": {
      "@id": "https://w3id.org/security#JsonWebSignature2020",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}`
