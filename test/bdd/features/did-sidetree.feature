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

    # domain2 server follows domain1 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://localhost:48326/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    Then we wait 3 seconds

  @create_valid_did_doc
  Scenario: create valid did doc
    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    # retrieve document with initial value before it becomes available on the ledger
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with initial state
    Then check success response contains "#did"
    Then check success response does NOT contain "canonicalId"

    Then we wait 2 seconds
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "#did"
    Then check success response contains "canonicalId"

    # resolve did on the second server within same domain (organisation)
    When client sends request to "https://orb2.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "#did"
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical id
    Then check success response contains "#canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with alias "did:orb:alias.com"
    Then check success response contains "#canonicalId"
    Then check success response contains "#aliasdid"

    # retrieve document with initial value after it becomes available on the ledger
    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with initial state
    Then check success response contains "#did"

  @create_deactivate_did_doc
  Scenario: deactivate valid did doc
    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "#did"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to deactivate DID document
    Then check for request success
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "deactivated"

  @create_recover_did_doc
  Scenario: recover did doc
    When client discover orb endpoints
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#did"
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
    Then check for request success
    Then we wait 2 seconds

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
    Then check success response contains "recoveryKey"
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical id
    Then check success response contains "#canonicalId"

    @create_add_remove_public_key
    Scenario: add and remove public keys
      When client discover orb endpoints
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "newKey" to DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "newKey"
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to remove public key with ID "newKey" from DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response does NOT contain "newKey"

    @create_add_remove_services
    Scenario: add and remove service endpoints
      When client discover orb endpoints
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add service endpoint with ID "newService" to DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "newService"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to remove service endpoint with ID "newService" from DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response does NOT contain "newService"
