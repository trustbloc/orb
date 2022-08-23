#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-sidetree
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"

    Given variable "domain1ID" is assigned the value "${domain1IRI}"
    And variable "domain2ID" is assigned the value "did:web:orb.domain2.com:services:orb"

    Given host "orb.domain1.com" is mapped to "localhost:48326"
    And host "orb2.domain1.com" is mapped to "localhost:48526"
    And host "orb.domain2.com" is mapped to "localhost:48426"
    And host "orb.domain3.com" is mapped to "localhost:48626"

    Given anchor origin for host "orb.domain1.com" is set to "https://orb.domain1.com"
    And anchor origin for host "orb2.domain1.com" is set to "https://orb.domain1.com"
    And anchor origin for host "orb.domain2.com" is set to "https://orb.domain1.com"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/log" is set to "ADMIN_TOKEN"

    # set up logs for domains
    When an HTTP POST is sent to "https://orb.domain1.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"
    When an HTTP POST is sent to "https://orb.domain3.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"

    Then we wait 1 seconds

    # domain1 adds domain2 and domain3 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain1AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain2ID}","${domain3IRI}"]},{"type":"invite-witness","add":["${domain2ID}","${domain3IRI}"]}]'
    When an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${domain1AcceptList}" of type "application/json"

    # domain2 adds domain1 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain1ID}"]},{"type":"invite-witness","add":["${domain1ID}"]}]'
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${domain2AcceptList}" of type "application/json"

    # domain2 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2ID}","to":"${domain1IRI}","object":"${domain1ID}"}'
    When an HTTP POST is sent to "${domain2IRI}/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1ID}","to":"${domain2IRI}","object":"${domain2ID}"}'
    When an HTTP POST is sent to "${domain1IRI}/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1ID}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2ID}"}'
    When an HTTP POST is sent to "${domain1IRI}/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain2ID}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1ID}"}'
    When an HTTP POST is sent to "${domain2IRI}/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    Then we wait 3 seconds

  @create_valid_did_doc
  Scenario: create valid did doc
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#interimDID"
    Then check success response contains "equivalentId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
    Then check error response contains "not found"

    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with initial state
    Then check success response contains "#interimDID"
    Then check success response does NOT contain "canonicalId"

    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with hint "https:orb.domain1.com"
    Then check success response contains "canonicalId"

    # test for orb client resolving anchor origin from ipfs
    When client sends request to "localhost:5001" to request anchor origin

    # resolve did on the second server within same domain (organisation)
    When client sends request to "https://orb2.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "#canonicalDID"

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#interimDID"
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to deactivate DID document
    Then check for request success
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "deactivated"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
    Then check error response contains "document has been deactivated, no further operations are allowed"

  @create_recover_did_doc
  Scenario: recover did doc
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#interimDID"
    Then we wait 5 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
    Then check for request success
    Then we wait 5 seconds

    # send request with previous canonical did - new canonical did will be returned
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "recoveryKey"
    Then check success response contains "canonicalId"

    # send request with previous equivalent did
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with previous equivalent did
    Then check success response contains "recoveryKey"
    Then check success response contains "canonicalId"

    # send request with new canonical did
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "#canonicalDID"

    # send request with invalid canonical did (CID doesn't belong to resolved document)
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with invalid CID in canonical did
    Then check error response contains "not found"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
      And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

      When client discover orb endpoints
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "newKey" to DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "newKey"
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to remove public key with ID "newKey" from DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response does NOT contain "newKey"

      # three consecutive updates test: it will be handled in three batches

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "firstKey" to DID document
      Then check for request success

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "secondKey" to DID document
      Then check for request success

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "thirdKey" to DID document
      Then check for request success

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "firstKey"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "firstKey"
      Then check success response contains "secondKey"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "firstKey"
      Then check success response contains "secondKey"
      Then check success response contains "thirdKey"

    @create_add_remove_services
    Scenario: add and remove service endpoints
      Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
      And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

      When client discover orb endpoints
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add service endpoint with ID "newService" to DID document
      Then check for request success
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "newService"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to remove service endpoint with ID "newService" from DID document
      Then check for request success
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response does NOT contain "newService"

    @create_update_also_known_as
    Scenario: update also known as
      Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
      And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

      When client discover orb endpoints
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"
      Then check success response contains "alsoKnownAs"
      Then check success response contains "https://myblog.example/"
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"
      Then check success response contains "alsoKnownAs"
      Then check success response contains "https://myblog.example/"

      # test removing existing URI - success
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to remove also known as URI "https://myblog.example/" from DID document
      Then check for request success
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response does NOT contain "alsoKnownAs"

      # test adding new URI for document without also known as
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add also known as URI "newURI" to DID document
      Then check for request success
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "alsoKnownAs"
      Then check success response contains "newURI"

      # test adding additional also known as URI to document
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add also known as URI "additionalURI" to DID document
      Then check for request success
      Then we wait 5 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "alsoKnownAs"
      Then check success response contains "newURI"
      Then check success response contains "additionalURI"

    @did_retrieve_by_version_id_and_time
    Scenario: retrieve document by version ID and version time
        Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
        And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

        Then variable "tBeforeCreate" is assigned the current time

        Then we wait 1 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
        Then check success response contains "#interimDID"

        Then we wait 2 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
        Then check success response contains "canonicalId"
        Then the JSON path 'didDocumentMetadata.versionId' of the response is saved to variable "v0"
        Then variable "t0" is assigned the current time

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${v0}"
        Then check success response contains "createKey"

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${t0}"
        Then check success response contains "createKey"

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${tBeforeCreate}"
        Then check error response contains "no operations found for version time"

        Then we wait 1 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "firstKey" to DID document
        Then check for request success
        Then we wait 2 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
        Then check success response contains "firstKey"
        Then the JSON path 'didDocumentMetadata.versionId' of the response is saved to variable "v1"
        Then variable "t1" is assigned the current time

        Then client verifies resolved document

        Then we wait 1 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "secondKey" to DID document
        Then check for request success
        Then we wait 2 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
        Then check success response contains "secondKey"
        Then the JSON path 'didDocumentMetadata.versionId' of the response is saved to variable "v2"
        Then variable "t2" is assigned the current time

        Then client verifies resolved document

        Then we wait 1 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "thirdKey" to DID document
        Then check for request success
        Then we wait 2 seconds

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
        Then check success response contains "thirdKey"
        Then the JSON path 'didDocumentMetadata.versionId' of the response is saved to variable "v3"
        Then variable "t3" is assigned the current time

        Then client verifies resolved document

        # start version time queries
        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${t0}"
        Then check success response contains "createKey"
        Then check success response does NOT contain "firstKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${t1}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response does NOT contain "secondKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${t2}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response contains "secondKey"
        Then check success response does NOT contain "thirdKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${t3}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response contains "secondKey"
        Then check success response contains "thirdKey"

        Then client verifies resolved document

       Given variable "invalidVerTime" is assigned the value "invalid"
        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version time "${invalidVerTime}"
        Then check error response contains "failed to parse version time"

        # start version ID queries
        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${v0}"
        Then check success response contains "createKey"
        Then check success response does NOT contain "firstKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${v1}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response does NOT contain "secondKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${v2}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response contains "secondKey"
        Then check success response does NOT contain "thirdKey"

        Then client verifies resolved document

        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${v3}"
        Then check success response contains "createKey"
        Then check success response contains "firstKey"
        Then check success response contains "secondKey"
        Then check success response contains "thirdKey"

        Then client verifies resolved document

        Given variable "invalidVer" is assigned the value "invalid"
        When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did and version ID "${invalidVer}"
        Then check error response contains "'invalid' is not a valid versionId"

  @did_doc_lifecycle
  Scenario: various did doc operations
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#interimDID"
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add service endpoint with ID "newService" to DID document
    Then check for request success
    Then we wait 5 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "newService"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
    Then check for request success
    Then we wait 5 seconds

    # send request with previous canonical did - new canonical did will be returned
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "recoveryKey"
    Then check success response contains "canonicalId"

    # send request with new canonical did
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "#canonicalDID"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "newKey" to DID document
    Then check for request success
    Then we wait 5 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "newKey"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "anotherKey" to DID document
    Then check for request success
    Then we wait 5 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "anotherKey"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to deactivate DID document
    Then check for request success
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "deactivated"

  @did_web_doc
  Scenario: various did doc operations (domain3 has caching enabled)
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"

    # test did:web document not found
    When an HTTP GET is sent to "https://orb.domain3.com/scid/non-existent/did.json" and the returned status code is 404

    When client sends request to "https://orb.domain3.com/sidetree/v1/operations" to create DID document and the suffix is saved to variable "didSuffix"

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with interim did
    Then check success response contains "uAAA"

    # test unpublished existing DID
    When an HTTP GET is sent to "https://orb.domain3.com/scid/${didSuffix}/did.json"

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with interim did
    Then check success response contains "canonicalId"

    # test published did without corresponding did:web in also known as
    When an HTTP GET is sent to "https://orb.domain3.com/scid/${didSuffix}/did.json"

    When client sends request to "https://orb.domain3.com/sidetree/v1/operations" to add also known as URI "did:web:orb.domain3.com:scid:${didSuffix}" to DID document
    Then check for request success

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "did:web:orb.domain3.com:scid"

    # did:web ID is now available in alsoKnownAs
    When an HTTP GET is sent to "https://orb.domain3.com/scid/${didSuffix}/did.json"

    When client sends request to "https://orb.domain3.com/sidetree/v1/operations" to recover DID document
    Then check for request success

    # verify recover DID
    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "recoveryKey"

    # normally we would include alsoKnownAs part of recovery request - so no need to update after recovery
    When client sends request to "https://orb.domain3.com/sidetree/v1/operations" to add also known as URI "did:web:orb.domain3.com:scid:${didSuffix}" to DID document
    Then check for request success

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "did:web:orb.domain3.com:scid"

    # check did:web after recovery
    When an HTTP GET is sent to "https://orb.domain3.com/scid/${didSuffix}/did.json"

    When client sends request to "https://orb.domain3.com/sidetree/v1/operations" to deactivate DID document
    Then check for request success

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "deactivated"

    # check did:web after deactivate - should be 404 (not found)
    When an HTTP GET is sent to "https://orb.domain3.com/scid/${didSuffix}/did.json" and the returned status code is 404

  @did_sidetree_auth
  Scenario: Sidetree endpoint authorization
    Given client discover orb endpoints

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check error response contains "Unauthorized"

    # Unauthorized
    When an HTTP GET is sent to "https://orb.domain1.com/sidetree/v1/identifiers/did:orb:QmSvg9rNRDGADLoTsNVt56vCuyYxuf1uernuAWoPcm5oiS:EiDahnXxu4l4iSUXgZKW6nUnSF7_y6QIaY4ePuWEE4bz0Q" and the returned status code is 401
    When an HTTP GET is sent to "https://orb.domain1.com/cas/bafkreiatkubvbkdidscmqynkyls3iqaweqvthi7e6mbky2amuw3inxsi3y" and the returned status code is 401

    # Domain3 is open for reads
    When an HTTP GET is sent to "https://orb.domain3.com/sidetree/v1/identifiers/did:orb:QmSvg9rNRDGADLoTsNVt56vCuyYxuf1uernuAWoPcm5oiS:EiDahnXxu4l4iSUXgZKW6nUnSF7_y6QIaY4ePuWEE4bz0Q" and the returned status code is 404
    When an HTTP GET is sent to "https://orb.domain3.com/cas/bafkreiatkubvbkdidscmqynkyls3iqawdqvthi7e6nbky2amuw3inxsi3y" and the returned status code is 404

