
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb_driver
Feature: Using Orb driver
  Background: Setup
    # TODO: Replace this configuration to use the Orb CLI to update the accept list - Issue #865.
    Given the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"
    Given variable "domain1AcceptList" is assigned the JSON value '[{"type":"follow","add":["https://orb.domain2.com/services/orb"]}]'
    Then an HTTP POST is sent to "https://localhost:48326/services/orb/acceptlist" with content "${domain1AcceptList}" of type "application/json"
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"invite-witness","add":["https://orb.domain1.com/services/orb"]}]'
    Then an HTTP POST is sent to "https://localhost:48426/services/orb/acceptlist" with content "${domain2AcceptList}" of type "application/json"

  @orb_driver_e2e
  Scenario: test resolve did through driver
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    # domain2 server follows domain1 server
    When user create "follower" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "Follow"
    # domain1 invites domain2 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check cli created valid DID through universal resolver
