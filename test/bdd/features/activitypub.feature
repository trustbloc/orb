#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@activitypub
Feature:

  @activitypub_service
  Scenario: Get ActivityPub service
    When an HTTP GET is sent to "https://localhost:48326/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "https://orb.domain1.com/services/orb/inbox"
    And the JSON path "outbox" of the response equals "https://orb.domain1.com/services/orb/outbox"
    And the JSON path "followers" of the response equals "https://orb.domain1.com/services/orb/followers"
    And the JSON path "following" of the response equals "https://orb.domain1.com/services/orb/following"
    And the JSON path "liked" of the response equals "https://orb.domain1.com/services/orb/liked"
    And the JSON path "witnesses" of the response equals "https://orb.domain1.com/services/orb/witnesses"
    And the JSON path "witnessing" of the response equals "https://orb.domain1.com/services/orb/witnessing"

    When an HTTP GET is sent to "https://localhost:48426/services/orb"
    Then the JSON path "type" of the response equals "Service"
    And the JSON path "inbox" of the response equals "https://orb.domain2.com/services/orb/inbox"
    And the JSON path "outbox" of the response equals "https://orb.domain2.com/services/orb/outbox"
    And the JSON path "followers" of the response equals "https://orb.domain2.com/services/orb/followers"
    And the JSON path "following" of the response equals "https://orb.domain2.com/services/orb/following"
    And the JSON path "liked" of the response equals "https://orb.domain2.com/services/orb/liked"
    And the JSON path "witnesses" of the response equals "https://orb.domain2.com/services/orb/witnesses"
    And the JSON path "witnessing" of the response equals "https://orb.domain2.com/services/orb/witnessing"

  @activitypub_follow
  Scenario: Follow ActivityPub service
    # domain2 follows domain1
    When an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content from file "./fixtures/testdata/follow_activity.json"

    Then we wait 3 seconds

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox"
    Then the JSON path "type" of the response equals "OrderedCollection"
    And the JSON path "id" of the response equals "https://orb.domain1.com/services/orb/inbox"
    And the JSON path "first" of the response equals "https://orb.domain1.com/services/orb/inbox?page=true"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "https://orb.domain2.com/services/orb/activities/97b3d005-abb6-422d-a889-18bc1ee84988"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "https://orb.domain1.com/services/orb/followers"
    And the JSON path "first" of the response equals "https://orb.domain1.com/services/orb/followers?page=true"

    When an HTTP GET is sent to "https://localhost:48326/services/orb/followers?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "https://orb.domain2.com/services/orb"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/following"
    Then the JSON path "type" of the response equals "Collection"
    And the JSON path "id" of the response equals "https://orb.domain2.com/services/orb/following"
    And the JSON path "first" of the response equals "https://orb.domain2.com/services/orb/following?page=true"

    When an HTTP GET is sent to "https://localhost:48426/services/orb/following?page=true"
    Then the JSON path "type" of the response equals "CollectionPage"
    And the JSON path "items" of the response contains "https://orb.domain1.com/services/orb"

  @activitypub_create
  Scenario: Create/announce
    # domain2 follows domain1
    When an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content from file "./fixtures/testdata/follow_activity.json"

    Then we wait 2 seconds

    # Post 'Create' activity to domain1
    When an HTTP POST is sent to "https://localhost:48326/services/orb/inbox" with content from file "./fixtures/testdata/create_activity.json"

    Then we wait 2 seconds

    When an HTTP GET is sent to "https://localhost:48326/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.id" of the response contains "https://orb.domain1.com/services/orb/activities/77bdd005-bbb6-223d-b889-58bc1de84985"

    # An 'Announce' activity should have been posted to domain1's followers (domain2).
    When an HTTP GET is sent to "https://localhost:48326/services/orb/outbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"

    # An 'Announce' activity should have been received by domain2 since it's a follower of domain1.
    When an HTTP GET is sent to "https://localhost:48426/services/orb/inbox?page=true"
    Then the JSON path "type" of the response equals "OrderedCollectionPage"
    And the JSON path "orderedItems.#.type" of the response contains "Announce"
