#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@did-orb
Feature:
  Background: Setup
    Given host-meta document is uploaded to IPNS
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain3IRI" is assigned the value "https://orb.domain3.com/services/orb"
    And variable "domain4IRI" is assigned the value "https://orb.domain4.com/services/orb"

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
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain1IRI}/activities/${followID}","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain3 server follows domain1 server. Domain3 needs to be a follower of domain1 so that HTTP signature validation succeeds when
    # the /cas endpoint is invoked on domain1 (since only followers and witnesses are authorized).
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain3IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"Invite","actor":"${domain1IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"id":"${domain2IRI}/activities/${inviteWitnessID}","type":"Invite","actor":"${domain2IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # set witness policy for domain1
    When an HTTP POST is sent to "https://orb.domain1.com/policy" with content "MinPercent(100,batch) AND MinPercent(50,system)" of type "text/plain"

    Then we wait 3 seconds

    @discover_did_hashlink
    Scenario: discover did (hashlink)
      When client discover orb endpoints

      # orb-domain1 keeps accepting requests
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "recoveryKey"
      Then check success response contains "#canonicalDID"

      # resolve did in domain4 - it will trigger did discovery in different organisations
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
      Then check error response contains "not found"

      Then we wait 3 seconds
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

    @discover_did_https
    Scenario: discover did (https)
      When client discover orb endpoints

      # orb-domain1 keeps accepting requests
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to recover DID document
      Then check for request success
      Then we wait 2 seconds

      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "recoveryKey"
      Then check success response contains "#canonicalDID"

      # resolve did in domain4 - it will trigger did discovery in different organisations
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with hint "https:orb.domain1.com"
      Then check error response contains "not found"

      Then we wait 3 seconds
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with hint "https:orb.domain1.com"
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"
      Then check success response contains "recoveryKey"

    @follow_anchor_writer_domain1
    Scenario: domain2 server follows domain1 server (anchor writer)

      # send create request to domain1
      When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"

      # check that document is available on the first server of domain2
      Then we wait 2 seconds
      When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

    @follow_anchor_writer_domain2
    Scenario: domain1 server follows domain2 server (anchor writer)

      # send create request to domain2
      When client sends request to "https://orb.domain2.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      Then we wait 2 seconds
      When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#canonicalDID"

      # check that document is available on the first server of domain1
      Then we wait 2 seconds
      When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

      # check that document is available on the second server of domain1
      When client sends request to "https://orb2.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "#canonicalDID"

    @concurrent_requests_scenario
    Scenario: concurrent requests plus server shutdown tests

     # write batch of DIDs to multiple servers and check them
     When client sends request to "https://orb2.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests

     # Stop orb2.domain1. The other instance in the domain should process any pending operations since
     # we're using a durable operation queue.
     Then container "orb2-domain1" is stopped
     And we wait 3 seconds

     Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

     Then container "orb-domain1" is stopped
     Then container "orb-domain2" is stopped
     Then container "ipfs" is stopped

     Then container "orb-domain1" is started
     Then container "orb2-domain1" is started
     Then container "orb-domain2" is started
     Then container "ipfs" is started

     Then we wait 5 seconds

     # now that servers re-started we should check for DIDs that were created before shutdowns
     Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb2.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

     # write batch of DIDs to multiple servers again and check them
     When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb2.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests

     Then we wait 5 seconds
     Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb2.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

     When an HTTP GET is sent to "https://orb.domain1.com/services/orb/liked?page=true"
     Then the JSON path "type" of the response equals "OrderedCollectionPage"
     And the JSON path "orderedItems" of the array response is not empty
     And the JSON path "orderedItems.0.object.url" of the response is saved to variable "anchorHash"
     And the JSON path "orderedItems.0" of the raw response is saved to variable "likeActivity"
     And the JSON path "orderedItems.0.id" of the response is saved to variable "likeID"
     And the JSON path "orderedItems.0.actor" of the response is saved to variable "likeActor"
     And the JSON path "orderedItems.0.to" of the raw response is saved to variable "likeTo"

     When an HTTP GET is sent to "https://orb.domain2.com/services/orb/likes?id=${anchorHash}&page=true"
     Then the JSON path "type" of the response equals "OrderedCollectionPage"
     And the JSON path "orderedItems" of the array response is not empty
     And the JSON path "orderedItems.0.object.url" of the response equals "${anchorHash}"

     Given variable "undoLikeActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${likeActor}","to":#{likeTo},"object":#{likeActivity}}'
     When an HTTP POST is sent to "${likeActor}/outbox" with content "${undoLikeActivity}" of type "application/json"

     Then we wait 2 seconds

     When an HTTP GET is sent to "https://orb.domain1.com/services/orb/liked?page=true"
     Then the JSON path "orderedItems.0.object.url" of the response does not contain "${anchorHash}"

     When an HTTP GET is sent to "https://orb.domain2.com/services/orb/likes?id=${anchorHash}&page=true"
     Then the JSON path "orderedItems.#" of the response has 0 items

    @enable_create_document_store_interim
    Scenario: domain4 has create document store enabled (interim DID)

      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      # since domain4 has create document store enabled we are able to resolve did document immediately from the store
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#interimDID"
      Then check success response does NOT contain "canonicalId"

      Then we wait 3 seconds
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

    @enable_create_document_store_interim_with_hint
    Scenario: domain4 has create document store enabled (interim DID with hint)

      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve interim DID document with hint "https:orb.domain4.com"
      Then check success response does NOT contain "canonicalId"


