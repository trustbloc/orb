
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb_stress
Feature: Using Orb stress test
  @orb_did_stress_test_setup
  Scenario:
    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"

    And the authorization bearer token for "POST" requests to path "/log" is set to "ADMIN_TOKEN"

    # set up logs for domains
    When an HTTP POST is sent to "https://orb.domain1.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"
    When an HTTP POST is sent to "https://orb.domain2.com/log" with content "" of type "text/plain"

    Given orb-cli is executed with args 'acceptlist add --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domain2.com/services/orb --type follow --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'
    And orb-cli is executed with args 'acceptlist add --url https://localhost:48426/services/orb/acceptlist --actor https://orb.domain1.com/services/orb --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'
    # domain2 server follows domain1 server
    When user create "follower" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "Follow"
      # domain1 invites domain2 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"

  @orb_did_stress_test
  Scenario:
    When client sends request to "ORB_STRESS_DID_DOMAINS" to create and update "ORB_STRESS_DID_NUMS" DID documents using "ORB_STRESS_CONCURRENT_REQ" concurrent requests with auth token "ORB_AUTH_TOKEN"
