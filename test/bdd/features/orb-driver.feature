
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@orb_driver
Feature: Using Orb driver
  Background: Setup
      And domain "orb.domain2.com" is mapped to "localhost:48426"
      And domain "orb.domain3.com" is mapped to "localhost:48626"

      Given the authorization bearer token for "POST" requests to path "/log" is set to "ADMIN_TOKEN"

      # set up logs for domains
      When an HTTP POST is sent to "https://orb.domain3.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"

    And orb-cli is executed with args 'acceptlist add --url https://localhost:48426/services/orb/acceptlist --actor https://orb.domain3.com/services/orb --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'

  @orb_driver_e2e
  Scenario: test resolve did through driver
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    # domain2 server follows domain1 server
    When user create "follower" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain3.com/services/orb" action "Follow"
    # domain1 invites domain2 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48626/services/orb/outbox" actor "https://orb.domain3.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When client sends request to "https://localhost:48626/sidetree/v1/operations" to create DID document
    Then check cli created valid DID through universal resolver
