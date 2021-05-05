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

  @activitypub_service
  Scenario: Get ActivityPub service
    When an HTTP GET is sent to "https://localhost:48326/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "${domain1IRI}/inbox"
    And the JSON path "outbox" of the response equals "${domain1IRI}/outbox"
    And the JSON path "followers" of the response equals "${domain1IRI}/followers"
    And the JSON path "following" of the response equals "${domain1IRI}/following"
    And the JSON path "liked" of the response equals "${domain1IRI}/liked"
    And the JSON path "witnesses" of the response equals "${domain1IRI}/witnesses"
    And the JSON path "witnessing" of the response equals "${domain1IRI}/witnessing"
    And the JSON path "publicKey.id" of the response equals "${domain1IRI}/keys/main-key"

    When an HTTP GET is sent to "https://localhost:48426/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "${domain2IRI}/inbox"
    And the JSON path "outbox" of the response equals "${domain2IRI}/outbox"
    And the JSON path "followers" of the response equals "${domain2IRI}/followers"
    And the JSON path "following" of the response equals "${domain2IRI}/following"
    And the JSON path "liked" of the response equals "${domain2IRI}/liked"
    And the JSON path "witnesses" of the response equals "${domain2IRI}/witnesses"
    And the JSON path "witnessing" of the response equals "${domain2IRI}/witnessing"
    And the JSON path "publicKey.id" of the response equals "${domain2IRI}/keys/main-key"

  @activitypub_pubkey
  Scenario: Get service public key
    When an HTTP GET is sent to "https://localhost:48326/services/orb/keys/main-key"
    Then the JSON path "id" of the response equals "https://orb.domain1.com/services/orb/keys/main-key"
    Then the JSON path "owner" of the response equals "https://orb.domain1.com/services/orb"
    Then the JSON path "publicKeyPem" of the response is not empty

    When an HTTP GET is sent to "https://localhost:48426/services/orb/keys/main-key"
    Then the JSON path "id" of the response equals "https://orb.domain2.com/services/orb/keys/main-key"
    Then the JSON path "owner" of the response equals "https://orb.domain2.com/services/orb"
    Then the JSON path "publicKeyPem" of the response is not empty

  @activitypub_follow
  Scenario: follow/accept/undo
    # domain2 follows domain1
    Given variable "followID" is assigned a unique ID
    Given variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${followActivity}" of type "application/json" signed with KMS key from "domain2"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollection"
    And the JSON path "id" of the response equals "${domain1IRI}/inbox"
    And the JSON path "first" of the response equals "${domain1IRI}/inbox?page=true"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain2IRI}/activities/${followID}"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain1IRI}/followers"
    And the JSON path "first" of the response equals "${domain1IRI}/followers?page=true"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain2IRI}"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/following" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain2IRI}/following"
    And the JSON path "first" of the response equals "${domain2IRI}/following?page=true"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/following?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain1IRI}"

    Given variable "undoID" is assigned a unique ID
    And variable "undoFollowActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${undoID}","type":"Undo","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain2IRI}/activities/${followID}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${undoFollowActivity}" of type "application/json" signed with KMS key from "domain2"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://localhost:48426/services/orb/following?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain1IRI}"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain2IRI}"

  @activitypub_create
  Scenario: create/announce
    # domain2 follows domain1
    Given variable "followDomain1Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${followDomain1Activity}" of type "application/json" signed with KMS key from "domain2"

    # domain3 follows domain2
    Given variable "follow2ID" is assigned a unique ID
    And variable "followDomain2Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","id":"${domain3IRI}/activities/${follow2ID}","actor":"${domain3IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://localhost:48626/services/orb/outbox" with content "${followDomain2Activity}" of type "application/json" signed with KMS key from "domain3"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://localhost:48426/services/orb/followers?page=true" signed with KMS key from "domain3"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain3IRI}"

    # Post 'Create' activity to domain1's outbox
    When an HTTP POST is sent to "https://localhost:48326/services/orb/outbox" with content from file "./fixtures/testdata/create_activity.json" signed with KMS key from "domain1"

    Then we wait 2 seconds

    # A 'Create' activity should have been posted to domain1's followers (domain2).
    When an HTTP GET is sent to "https://localhost:48426/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain1IRI}/activities/77bdd005-bbb6-223d-b889-58bc1de84985"

    # An 'Announce' activity should have been posted to domain2's followers (domain3).
    When an HTTP GET is sent to "https://localhost:48426/services/orb/outbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"

    # An 'Announce' activity should have been received by domain3 since it's a follower of domain2.
    When an HTTP GET is sent to "https://localhost:48626/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"

    And variable "undoFollow2Activity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Undo","actor":"${domain3IRI}","to":"${domain2IRI}","object":"${domain3IRI}/activities/${follow2ID}"}'
    When an HTTP POST is sent to "https://localhost:48626/services/orb/outbox" with content "${undoFollow2Activity}" of type "application/json" signed with KMS key from "domain3"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://localhost:48426/services/orb/followers?page=true" signed with KMS key from "domain3"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain3IRI}"

  @activitypub_invite_witness
  Scenario: invite witness/accept/undo
    # domain1 invites domain2 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain1IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://localhost:48326/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json" signed with KMS key from "domain1"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://localhost:48426/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain1IRI}/activities/${inviteWitnessID}"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/witnesses" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain1IRI}/witnesses"
    And the JSON path "first" of the response equals "${domain1IRI}/witnesses?page=true"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/witnesses?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain2IRI}"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/witnessing" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "${domain2IRI}/witnessing"
    And the JSON path "first" of the response equals "${domain2IRI}/witnessing?page=true"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/witnessing?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "${domain1IRI}"

    Given variable "undoWitnessID" is assigned a unique ID
    And variable "undoInviteWitnessActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain1IRI}/activities/${undoWitnessID}","type":"Undo","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain1IRI}/activities/${inviteWitnessID}"}'
    When an HTTP POST is sent to "https://localhost:48326/services/orb/outbox" with content "${undoInviteWitnessActivity}" of type "application/json" signed with KMS key from "domain1"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://localhost:48326/services/orb/witnesses?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain2IRI}"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/witnessing?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response does not contain "${domain1IRI}"

  @activitypub_offer
  Scenario: offer/like
    # domain2 invites domain1 to be a witness
    Given variable "inviteWitnessID" is assigned a unique ID
    Given variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"],"id":"${domain2IRI}/activities/${inviteWitnessID}","type":"InviteWitness","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json" signed with KMS key from "domain2"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain2IRI}/activities/${inviteWitnessID}"

    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content from file "./fixtures/testdata/offer_activity.json" signed with KMS key from "domain2"

    Then we wait 2 seconds

    # The 'Offer' activity should be in the inbox of domain1.
    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "${domain2IRI}/activities/63b3d005-6cb6-673d-6379-18be1ee84973"

    # The 'Like' should be in the 'liked' collection of domain1.
    When an HTTP GET is sent to "https://localhost:48326/services/orb/liked?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Like"
    And the JSON path "orderedItems.#.object" of the response contains "http://orb.domain2.com/transactions/bafkreihwsn"

    # A 'Like' activity should be in the inbox of domain2.
    When an HTTP GET is sent to "https://localhost:48426/services/orb/inbox?page=true" signed with KMS key from "domain1"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Like"
    And the JSON path "orderedItems.#.object" of the response contains "http://orb.domain2.com/transactions/bafkreihwsn"

  @activitypub_httpsig
  Scenario: Tests HTTP signature verification
    Given variable "followID" is assigned a unique ID
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","id":"${domain2IRI}/activities/${followID}","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'

    # No signature on POST
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${followActivity}" of type "application/json" and the returned status code is 401

    # Invalid signature on POST
    When an HTTP POST is sent to "https://localhost:48426/services/orb/outbox" with content "${followActivity}" of type "application/json" signed with KMS key from "domain1" and the returned status code is 401

    # No signature on GET
    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox" and the returned status code is 401
    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers" and the returned status code is 401
