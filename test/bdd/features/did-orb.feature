#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

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

    @all
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

    @all
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

    @all
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

    @all
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

    @all
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
     And the JSON path "orderedItems.0.object.url" of the response is saved to variable "anchorLink"
     And the JSON path "orderedItems.0" of the raw response is saved to variable "likeActivity"
     And the JSON path "orderedItems.0.id" of the response is saved to variable "likeID"
     And the JSON path "orderedItems.0.actor" of the response is saved to variable "likeActor"
     And the JSON path "orderedItems.0.to" of the raw response is saved to variable "likeTo"

     When an HTTP GET is sent to "https://orb.domain2.com/services/orb/likes?id=${anchorLink}&page=true"
     Then the JSON path "type" of the response equals "OrderedCollectionPage"
     # There should be two Like's:
     # 1 - From domain1 (which received the 'Create');
     # 2 - From domain3 (which received the 'Announce')
     And the JSON path "orderedItems.#" of the response has 2 items
     And the JSON path "orderedItems.#.actor" of the response contains "${domain1IRI}"
     And the JSON path "orderedItems.#.actor" of the response contains "${domain3IRI}"
     And the JSON path "orderedItems.0.object.url" of the response equals "${anchorLink}"

     When an HTTP GET is sent to "https://orb.domain1.com/services/orb/likes?id=${anchorLink}&page=true"
     Then the JSON path "type" of the response equals "OrderedCollectionPage"
     # There should be one Like:
     # 1 - From domain3 (which received the 'Announce')
     And the JSON path "orderedItems.#" of the response has 1 items
     And the JSON path "orderedItems.#.actor" of the response contains "${domain3IRI}"
     And the JSON path "orderedItems.0.object.url" of the response equals "${anchorLink}"

     Given variable "undoLikeActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${likeActor}","to":#{likeTo},"object":#{likeActivity}}'
     When an HTTP POST is sent to "${likeActor}/outbox" with content "${undoLikeActivity}" of type "application/json"

     Then we wait 2 seconds

     When an HTTP GET is sent to "https://orb.domain1.com/services/orb/liked?page=true"
     Then the JSON path "orderedItems.0.object.url" of the response does not contain "${anchorLink}"

     When an HTTP GET is sent to "https://orb.domain2.com/services/orb/likes?id=${anchorLink}&page=true"
     Then the JSON path "orderedItems.#" of the response has 1 items
     And the JSON path "orderedItems.#.actor" of the response contains "${domain3IRI}"

    @all
    @enable_create_document_store_interim
    Scenario: domain4 has create document store enabled (interim DID)

      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      # since domain4 has create document store enabled we are able to resolve did document immediately from the store
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#interimDID"
      Then check success response does NOT contain "canonicalId"

      Then we wait 6 seconds
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

    @all
    @enable_create_document_store_interim_with_hint
    Scenario: domain4 has create document store enabled (interim DID with hint)

      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve interim DID document with hint "https:orb.domain4.com"
      Then check success response does NOT contain "canonicalId"

    @all
    @enable_update_document_store
    Scenario: domain4 has update document store enabled

      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to create DID document
      Then check success response contains "#interimDID"

      # since domain4 has create document store enabled we are able to resolve did document immediately from the store
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "#interimDID"
      Then check success response does NOT contain "canonicalId"

      # re-try until create operation is published
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with interim did
      Then check success response contains "canonicalId"

      # now that create is published we can update document
      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to add public key with ID "firstKey" to DID document
      Then check for request success

      # update request can be immediately resolved
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "firstKey"

      # request second update while first one is pending - error expected
      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to add public key with ID "secondKey" to DID document
      Then check error response contains "pending operation found"
      Then check error response contains "please re-submit your operation request at later time"

      # wait for pending operation to clear
      Then we wait 6 seconds

      # re-send second update - since first one cleared it will be successful
      When client sends request to "https://orb.domain4.com/sidetree/v1/operations" to add public key with ID "secondKey" to DID document
      Then check for request success

      # resolve second update right away
      When client sends request to "https://orb.domain4.com/sidetree/v1/identifiers" to resolve DID document with canonical did
      Then check success response contains "secondKey"

  @local_cas
  @alternate_links_scenario
  Scenario: WebFinger query returns alternate links for "Liked" anchor credentials
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document and the ID is saved to variable "didID"
    Then we wait 3 seconds

    When an HTTP GET is sent to "https://orb.domain1.com/.well-known/webfinger?resource=${didID}"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain1\.com.*"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain2\.com.*"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain3\.com.*"
    And the JSON path 'links.#(rel=="via").href' of the response is saved to variable "anchorLink"
    And variable "anchorHash" is assigned the value "$hashlink(|${anchorLink}|).ResourceHash"

    When an HTTP GET is sent to "https://orb.domain1.com/.well-known/webfinger?resource=https://orb.domain1.com/cas/${anchorHash}"
    And the JSON path 'links.#(rel=="self").href' of the response equals "https://orb.domain1.com/cas/${anchorHash}"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain2\.com.*"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain3\.com.*"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/likes?id=${anchorLink}&page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#" of the response has 2 items
    And the JSON path "orderedItems.0" of the raw response is saved to variable "likeActivity_1"
    And the JSON path "orderedItems.0.actor" of the response is saved to variable "likeActor_1"
    And the JSON path "orderedItems.0.to" of the raw response is saved to variable "likeTo_1"
    And the JSON path "orderedItems.1" of the raw response is saved to variable "likeActivity_2"
    And the JSON path "orderedItems.1.actor" of the response is saved to variable "likeActor_2"
    And the JSON path "orderedItems.1.to" of the raw response is saved to variable "likeTo_2"

    # Undo the 'Like's from domain1 and domain2.
    Given variable "undoLikeActivity_1" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${likeActor_1}","to":#{likeTo_1},"object":#{likeActivity_1}}'
    And variable "undoLikeActivity_2" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${likeActor_2}","to":#{likeTo_2},"object":#{likeActivity_2}}'

    When an HTTP POST is sent to "${likeActor_1}/outbox" with content "${undoLikeActivity_1}" of type "application/json"
    And an HTTP POST is sent to "${likeActor_2}/outbox" with content "${undoLikeActivity_2}" of type "application/json"

    Then we wait 2 seconds

    # domain2 and domain 3 should no longer appear in the response of the WebFinger DID query.
    When an HTTP GET is sent to "https://orb.domain1.com/.well-known/webfinger?resource=${didID}"
    And the JSON path "links.#.href" of the response contains expression ".*orb\.domain1\.com.*"
    And the JSON path "links.#.href" of the response does not contain expression ".*orb\.domain2\.com.*"
    And the JSON path "links.#.href" of the response does not contain expression ".*orb\.domain3\.com.*"

    # domain2 and domain 3 should no longer appear in the response of the WebFinger CAS query.
    When an HTTP GET is sent to "https://orb.domain1.com/.well-known/webfinger?resource=https://orb.domain1.com/cas/${anchorHash}"
    And the JSON path 'links.#(rel=="self").href' of the response equals "https://orb.domain1.com/cas/${anchorHash}"
    And the JSON path "links.#.href" of the response does not contain expression ".*orb\.domain2\.com.*"
    And the JSON path "links.#.href" of the response does not contain expression ".*orb\.domain3\.com.*"
