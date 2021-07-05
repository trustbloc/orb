#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@activitypub
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain3IRI" is assigned the value "https://orb.domain3.com/services/orb"

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And domain "orb.domain3.com" is mapped to "localhost:48626"

  @activitypub_service
  Scenario: Get ActivityPub service
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "${domain1IRI}/inbox"
    And the JSON path "outbox" of the response equals "${domain1IRI}/outbox"
    And the JSON path "followers" of the response equals "${domain1IRI}/followers"
    And the JSON path "following" of the response equals "${domain1IRI}/following"
    And the JSON path "liked" of the response equals "${domain1IRI}/liked"
    And the JSON path "witnesses" of the response equals "${domain1IRI}/witnesses"
    And the JSON path "witnessing" of the response equals "${domain1IRI}/witnessing"
    And the JSON path "publicKey.id" of the response equals "${domain1IRI}/keys/main-key"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "${domain2IRI}/inbox"
    And the JSON path "outbox" of the response equals "${domain2IRI}/outbox"
    And the JSON path "followers" of the response equals "${domain2IRI}/followers"
    And the JSON path "following" of the response equals "${domain2IRI}/following"
    And the JSON path "liked" of the response equals "${domain2IRI}/liked"
    And the JSON path "likes" of the response equals "${domain2IRI}/likes"
    And the JSON path "witnesses" of the response equals "${domain2IRI}/witnesses"
    And the JSON path "witnessing" of the response equals "${domain2IRI}/witnessing"
    And the JSON path "publicKey.id" of the response equals "${domain2IRI}/keys/main-key"
    And the JSON path "shares" of the response equals "${domain2IRI}/shares"

  @activitypub_pubkey
  Scenario: Get service public key
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/keys/main-key"
    Then the JSON path "id" of the response equals "https://orb.domain1.com/services/orb/keys/main-key"
    Then the JSON path "owner" of the response equals "https://orb.domain1.com/services/orb"
    Then the JSON path "publicKeyPem" of the response is not empty

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/keys/main-key"
    Then the JSON path "id" of the response equals "https://orb.domain2.com/services/orb/keys/main-key"
    Then the JSON path "owner" of the response equals "https://orb.domain2.com/services/orb"
    Then the JSON path "publicKeyPem" of the response is not empty

  @activitypub_follow
  Scenario: follow/accept/undo
    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"

    # domain2 follows domain1
    Given variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "followID"

    Then we wait 3 seconds

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "READ_TOKEN"

    When an HTTP GET is sent to "${followID}"
    Then the JSON path "id" of the response equals "${followID}"
    And the JSON path "type" of the response equals "Follow"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox"
    Then the JSON path "type" of the response equals "OrderedCollection"
    And the JSON path "id" of the response equals "${domain1IRI}/inbox"
    And the JSON path "first" of the response equals "${domain1IRI}/inbox?page=true"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${followID}"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/followers"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain1IRI}/followers"
    And the JSON path "first" of the response equals "${domain1IRI}/followers?page=true"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/followers?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain2IRI}"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/following"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain2IRI}/following"
    And the JSON path "first" of the response equals "${domain2IRI}/following?page=true"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/following?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain1IRI}"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"

    And variable "undoFollowActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${followID}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${undoFollowActivity}" of type "application/json"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/following?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain1IRI}"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/followers?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain2IRI}"

  @activitypub_create
  Scenario: create/announce
    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"

    # domain2 follows domain1
    Given variable "followDomain1Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followDomain1Activity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "follow1ID"

    # domain3 follows domain2
    And variable "followDomain2Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain3IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${followDomain2Activity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "follow2ID"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/followers?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain3IRI}"

    # Post 'Create' activity to domain1's outbox
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content from file "./fixtures/testdata/create_activity.json"

    Then we wait 2 seconds

    # A 'Create' activity should have been posted to domain1's followers (domain2).
    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain1IRI}/activities/77bdd005-bbb6-223d-b889-58bc1de84985"

    # An 'Announce' activity should have been posted to domain2's followers (domain3).
    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/outbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"

    # An 'Announce' activity should have been received by domain3 since it's a follower of domain2.
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"

    And variable "undoFollow1Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${follow1ID}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${undoFollow1Activity}" of type "application/json"

    And variable "undoFollow2Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain3IRI}","to":"${domain2IRI}","object":"${follow2ID}"}'
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${undoFollow2Activity}" of type "application/json"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/followers?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain3IRI}"

    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/shares?id=https%3A%2F%2Forb.domain1.com%2Ftransactions%2Fbafkreiduenhjrl7hjgh3lwxr6nvmfv4kzqzzizhzkbydxdabtcjptavzbm"
    Then the JSON path "type" of the response equals "OrderedCollection"
    Then the JSON path "first" of the response is saved to variable "sharesFirstPage"
    When an HTTP GET is sent to "${sharesFirstPage}"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.0.object.items.0.id" of the response equals "https://orb.domain1.com/transactions/bafkreiduenhjrl7hjgh3lwxr6nvmfv4kzqzzizhzkbydxdabtcjptavzbm"

  @activitypub_invite_witness
  Scenario: invite witness/accept/undo
    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"

    # domain1 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"type":"InviteWitness","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "inviteWitnessID"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${inviteWitnessID}"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/witnesses"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain1IRI}/witnesses"
    And the JSON path "first" of the response equals "${domain1IRI}/witnesses?page=true"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/witnesses?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain2IRI}"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/witnessing"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain2IRI}/witnessing"
    And the JSON path "first" of the response equals "${domain2IRI}/witnessing?page=true"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/witnessing?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain1IRI}"

    And variable "undoInviteWitnessActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${inviteWitnessID}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${undoInviteWitnessActivity}" of type "application/json"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/witnesses?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain2IRI}"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/witnessing?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain1IRI}"

  @activitypub_offer
  Scenario: offer/like
    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"

    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"type":"InviteWitness","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "inviteWitnessID"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${inviteWitnessID}"

    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content from file "./fixtures/testdata/offer_activity.json"

    Then we wait 2 seconds

    # The 'Offer' activity should be in the inbox of domain1.
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain2IRI}/activities/63b3d005-6cb6-673d-6379-18be1ee84973"

    # The 'Like' should be in the 'liked' collection of domain1.
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/liked?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Like"
    And the JSON path "orderedItems.#.object" of the response contains "http://orb.domain2.com/transactions/bafkreihwsn"

    # A 'Like' activity should be in the inbox of domain2.
    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Like"
    And the JSON path "orderedItems.#.object" of the response contains "http://orb.domain2.com/transactions/bafkreihwsn"

    And variable "undoInviteWitnessActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${inviteWitnessID}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${undoInviteWitnessActivity}" of type "application/json"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/witnessing?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain1IRI}"

  @activitypub_httpsig
  Scenario: Tests HTTP signature verification
    Given variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'

    # No signature on POST
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json" and the returned status code is 401

    # Invalid signature on POST
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json" signed with KMS key from "domain1" and the returned status code is 401

    # Valid signature on POST
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json" signed with KMS key from "domain2"
    Then the value of the JSON string response is saved to variable "followID"

    Then we wait 2 seconds

    # No signature on GET
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox" and the returned status code is 401
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/followers" and the returned status code is 401

    # Valid signature on GET with actor as a follower - should be allowed
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox" signed with KMS key from "domain2"
    Then the JSON path "type" of the response equals "OrderedCollection"

    # Valid signature on GET with actor as non-follower/non-witness - should be denied
    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox" signed with KMS key from "domain3" and the returned status code is 401

    And variable "undoFollowActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${followID}"}'
    Then an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${undoFollowActivity}" of type "application/json" signed with KMS key from "domain2"

  @activitypub_auth_token
  Scenario: Tests authorization tokens
    # No auth token or signature on POST
    Given variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json" and the returned status code is 401
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/inbox" with content "${followActivity}" of type "application/json" and the returned status code is 401
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${followActivity}" of type "application/json" and the returned status code is 401

    # Set auth token
    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "followID"

    Then we wait 2 seconds

    And variable "undoFollowActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain2IRI}","to":["${domain1IRI}","https://www.w3.org/ns/activitystreams#Public"],"object":"${followID}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${undoFollowActivity}" of type "application/json"
    Then the value of the JSON string response is saved to variable "undoFollowID"

    # No auth token or signature on GET
    When an HTTP GET is sent to "${followID}" and the returned status code is 401
    And an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox" and the returned status code is 401

    # Domain3 doesn't require authorization for reads
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/inbox"
    Then the JSON path "type" of the response equals "OrderedCollection"
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/outbox"
    Then the JSON path "type" of the response equals "OrderedCollection"
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/followers"
    Then the JSON path "type" of the response equals "Collection"
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/witnesses"
    Then the JSON path "type" of the response equals "Collection"
    When an HTTP GET is sent to "https://orb.domain3.com/services/orb/liked"
    Then the JSON path "type" of the response equals "OrderedCollection"

    # Activities that are sent to https://www.w3.org/ns/activitystreams#Public don't require authentication
    When an HTTP GET is sent to "${undoFollowID}"
    Then the JSON path "type" of the response equals "Undo"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/outbox?page=true"
    # Public activities should be returned
    Then the JSON path "orderedItems.#.id" of the response contains "${undoFollowID}"
    # Non-public activities should be excluded with no authentication
    And the JSON path "orderedItems.#.id" of the response does not contain "${followID}"

    # Set auth tokens
    Given the authorization bearer token for "GET" requests to path "/services/orb/activities" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb/inbox" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb/outbox" is set to "READ_TOKEN"

    When an HTTP GET is sent to "${followID}"
    Then the JSON path "type" of the response equals "Follow"

    When an HTTP GET is sent to "https://orb.domain1.com/services/orb/inbox"
    Then the JSON path "type" of the response equals "OrderedCollection"

    When an HTTP GET is sent to "https://orb.domain2.com/services/orb/outbox?page=true"
    Then the JSON path "orderedItems.#.id" of the response contains "${undoFollowID}"
    And the JSON path "orderedItems.#.id" of the response contains "${followID}"
