
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb_cli
Feature: Using Orb CLI
  Background: Setup

  @orb_cli_did
  Scenario: test create and update did doc using cli
    # domain2 server follows domain1 server
    When user create "follower" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "Follow"
    # domain1 invites domain2 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When Orb DID is created through cli
    Then check cli created valid DID
    When Orb DID is updated through cli
    Then check cli updated DID
    When Orb DID is recovered through cli
    Then check cli recovered DID
    When Orb DID is deactivated through cli
    Then check cli deactivated DID

  @orb_cli_activity
  Scenario: test follow and witness
    # domain1 server follows domain2 server
    When user create "follower" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "Follow"
    Then we wait 3 seconds
    When user create "follower" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "Undo"

      # domain2 invites domain1 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When user create "witness" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "Undo"
