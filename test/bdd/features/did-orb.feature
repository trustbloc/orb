#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-orb
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "http://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "http://orb.domain2.com/services/orb"
    And variable "domain3IRI" is assigned the value "http://orb.domain3.com/services/orb"
    And variable "domain4IRI" is assigned the value "http://orb.domain4.com/services/orb"

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And domain "orb.domain3.com" is mapped to "localhost:48626"
    And domain "orb.domain4.com" is mapped to "localhost:48726"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/policy" is set to "ADMIN_TOKEN"

    # domain2 server follows domain1 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "http://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain1IRI}/activities/${followID}","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "http://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain3 server follows domain1 server. Domain3 needs to be a follower of domain1 so that HTTP signature validation succeeds when
    # the /cas endpoint is invoked on domain1 (since only followers and witnesses are authorized).
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain3IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "http://orb.domain3.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","http://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "http://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","http://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain2IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "http://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # set witness policy for domain1
    When an HTTP POST is sent to "http://orb.domain1.com/policy" with content "MinPercent(100,batch) AND MinPercent(50,system)" of type "text/plain"

    Then we wait 3 seconds

    @discover_did
    Scenario: discover did
      When client discover orb endpoints

      # orb-domain1 keeps accepting requests
      When client sends request to "http://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "http://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

      When client sends request to "http://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      When client sends request to "http://orb.domain1.com/sidetree/v1/operations" to recover DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "http://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "recoveryKey"
      Then check success response contains "#canonicalDID"

      # resolve did in domain4 - it will trigger did discovery in different organisations
      When client sends request to "http://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
      Then check error response contains "not found"

      Then we wait 2 seconds
      When client sends request to "http://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

      When client sends request to "http://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

    @follow_anchor_writer_domain1
    Scenario: domain2 server follows domain1 server (anchor writer)

      # send create request to domain1
      When client sends request to "http://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "http://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"

      # check that document is available on the first server of domain2
      Then we wait 2 seconds
      When client sends request to "http://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

    @follow_anchor_writer_domain2
    Scenario: domain1 server follows domain2 server (anchor writer)

      # send create request to domain2
      When client sends request to "http://orb.domain2.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "http://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"

      # check that document is available on the first server of domain1
      Then we wait 2 seconds
      When client sends request to "http://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      # check that document is available on the second server of domain1
      When client sends request to "http://orb2.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

    @concurrent_requests_scenario
    Scenario: concurrent requests plus server shutdown tests

     # write batch of DIDs to multiple servers and check them
     When client sends request to "http://orb2.domain1.com/sidetree/v1/operations,http://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests

     # Stop orb2.domain1. The other instance in the domain should process any pending operations since
     # we're using a durable operation queue.
     Then container "orb2-domain1" is stopped
     And we wait 3 seconds

     Then client sends request to "http://orb.domain1.com/sidetree/v1/identifiers,http://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

     Then container "orb-domain1" is stopped
     Then container "orb-domain2" is stopped
     Then container "ipfs" is stopped

     Then container "orb-domain1" is started
     Then container "orb2-domain1" is started
     Then container "orb-domain2" is started
     Then container "ipfs" is started

     Then we wait 5 seconds

     # now that servers re-started we should check for DIDs that were created before shutdowns
     Then client sends request to "http://orb.domain1.com/sidetree/v1/identifiers,http://orb2.domain1.com/sidetree/v1/identifiers,http://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

     # write batch of DIDs to multiple servers again and check them
     When client sends request to "http://orb.domain1.com/sidetree/v1/operations,http://orb2.domain1.com/sidetree/v1/operations,http://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests

     Then we wait 5 seconds
     Then client sends request to "http://orb.domain1.com/sidetree/v1/identifiers,http://orb2.domain1.com/sidetree/v1/identifiers,http://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

    @enable_create_document_store
    Scenario: domain4 has create document store enabled

      When client sends request to "http://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      # since domain4 has create document store enabled we are able to resolve did document immediately from the store
      When client sends request to "http://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#interimDID"
      Then check success response does NOT contain "canonicalId"

      Then we wait 3 seconds
      When client sends request to "http://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"
