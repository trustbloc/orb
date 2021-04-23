#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-orb
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain1KeyID" is assigned the value "${domain1IRI}/keys/main-key"
    And variable "domain1KeyFile" is assigned the value "./fixtures/testdata/keys/domain1/private-key.pem"

    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain2KeyID" is assigned the value "${domain2IRI}/keys/main-key"
    And variable "domain2KeyFile" is assigned the value "./fixtures/testdata/keys/domain2/private-key.pem"

    # domain2 server follows domain1 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content "${followActivity}" of type "application/json" signed with private key from file "${domain2KeyFile}" using key ID "${domain2KeyID}"

    # domain1 server follows domain2 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain1IRI}/activities/${followID}","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/inbox" with content "${followActivity}" of type "application/json" signed with private key from file "${domain1KeyFile}" using key ID "${domain1KeyID}"

    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/inbox" with content "${inviteWitnessActivity}" of type "application/json" signed with private key from file "${domain1KeyFile}" using key ID "${domain1KeyID}"

    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain2IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content "${inviteWitnessActivity}" of type "application/json" signed with private key from file "${domain2KeyFile}" using key ID "${domain2KeyID}"

    Then we wait 3 seconds

    @discover_did
    Scenario: discover did
      When client discover orb endpoints

      Then container "orb-domain3" is stopped
      Then we wait 3 seconds

      # orb-domain1 keeps accepting requests
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "recoveryKey"
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"
      Then check success response contains "recoveryKey"

      Then container "orb-domain3" is started
      Then we wait 10 seconds

      # resolve did in domain3 - it will trigger did discovery in different organisations
      When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check error response contains "not found"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical id
      Then check success response contains "#canonicalId"
      Then check success response contains "recoveryKey"

    @follow_anchor_writer_domain1
    Scenario: domain2 server follows domain1 server (anchor writer)

      # send create request to domain1
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

      # check that document is available on the first server of domain2
      Then we wait 2 seconds
      When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

    @follow_anchor_writer_domain2
    Scenario: domain1 server follows domain2 server (anchor writer)

      # send create request to domain2
      When client sends request to "https://orb.domain2.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#did"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

      # check that document is available on the first server of domain1
      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"

      # check that document is available on the second server of domain1
      When client sends request to "https://orb2.domain1.com/sidetree/v1/identifiers" to resolve DID document
      Then check success response contains "#did"
