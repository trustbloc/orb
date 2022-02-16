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

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And domain "orb.domain3.com" is mapped to "localhost:48626"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"

    # domain1 adds domain2 and domain3 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain1AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain2IRI}","${domain3IRI}"]},{"type":"invite-witness","add":["${domain2IRI}","${domain3IRI}"]}]'
    When an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${domain1AcceptList}" of type "application/json"

    # domain2 adds domain1 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain1IRI}"]},{"type":"invite-witness","add":["${domain1IRI}"]}]'
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${domain2AcceptList}" of type "application/json"

    # domain2 server follows domain1 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain1IRI}/activities/${followID}","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"Invite","actor":"${domain1IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"id":"${domain2IRI}/activities/${inviteWitnessID}","type":"Invite","actor":"${domain2IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

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
