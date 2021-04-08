#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-sidetree
Feature:
  Background: Setup
    And variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"

  @create_valid_did_doc
  Scenario: create valid did doc
    When client discover orb endpoints
    When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with initial state
    Then check success response contains "#did"
    Then check success response does NOT contain "canonicalId"

    Then we wait 3 seconds
    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "#did"
    Then check success response contains "canonicalId"

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
    Then check success response contains "#canonicalId"

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with alias "did:alias.com"
    Then check success response contains "#canonicalId"
    Then check success response contains "#aliasdid"

    # retrieve document with initial value after it becomes available on the ledger
    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with initial state
    Then check success response contains "#did"

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    When client discover orb endpoints
    When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    Then we wait 3 seconds

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "#did"

    When client sends request to "https://localhost:48326/sidetree/v1/operations" to deactivate DID document
    Then we wait 3 seconds

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "deactivated"

  @create_recover_did_doc
  Scenario: recover did doc
    When client discover orb endpoints
    When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    Then we wait 3 seconds

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "canonicalId"

    When client sends request to "https://localhost:48326/sidetree/v1/operations" to recover DID document
    Then we wait 3 seconds

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "recoveryKey"
    Then check success response contains "canonicalId"

    When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
    Then check success response contains "#canonicalId"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      When client discover orb endpoints
      When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to add public key with ID "newKey" to DID document
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "newKey"
      Then check success response contains "canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to remove public key with ID "newKey" from DID document
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response does NOT contain "newKey"

    @create_add_remove_services
    Scenario: add and remove service endpoints
      When client discover orb endpoints
      When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to add service endpoint with ID "newService" to DID document
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "newService"

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to remove service endpoint with ID "newService" from DID document
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response does NOT contain "newService"

    @discover_did
    Scenario: discover did
      When client discover orb endpoints
      When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"

      Then we wait 3 seconds
      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"
      Then check success response contains "canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to recover DID document
      Then we wait 3 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "recoveryKey"
      Then check success response contains "canonicalId"

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"
      Then check success response contains "recoveryKey"

      Then container "orb-domain1" is stopped
      Then we wait 3 seconds

      Then container "orb-domain1" is started
      Then we wait 15 seconds

      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check error response contains "not found"

      Then we wait 5 seconds
      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"
      Then check success response contains "recoveryKey"

    @follow_anchor_writer
    Scenario: second server follows first server (anchor writer)

      # domain2 follows domain1
      Given variable "followID" is assigned a unique ID
      And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
      Then an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content "${followActivity}" of type "application/json"

      When client sends request to "https://localhost:48326/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"

      Then we wait 3 seconds
      When client sends request to "https://localhost:48326/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

      # check second server for document
      Then we wait 5 seconds
      When client sends request to "https://localhost:48426/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"
