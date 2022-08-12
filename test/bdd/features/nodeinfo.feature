#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@nodeinfo
Feature: NodeInfo
  Background: Setup
    Given host "orb.domain1.com" is mapped to "localhost:48326"

  @node_info
  Scenario: Tests NodeInfo response from the server
    When an HTTP GET is sent to "https://orb.domain1.com/.well-known/nodeinfo"
    Then the JSON path "links.#.rel" of the response contains "http://nodeinfo.diaspora.software/ns/schema/2.0"
    And the JSON path "links.#.rel" of the response contains "http://nodeinfo.diaspora.software/ns/schema/2.1"
    And the JSON path "links.#.href" of the response contains "https://orb.domain1.com/nodeinfo/2.0"
    And the JSON path "links.#.href" of the response contains "https://orb.domain1.com/nodeinfo/2.1"

    When an HTTP GET is sent to "https://orb.domain1.com/nodeinfo/2.1"
    Then the JSON path "software.name" of the response equals "Orb"
    And the JSON path "software.repository" of the response equals "https://github.com/trustbloc/orb"
    And the JSON path "usage.users.total" of the numeric response equals "1"
