
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@orb_cli
Feature: Using Orb CLI
  Background: Setup
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And orb-cli is executed with args 'acceptlist add --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domain2.com/services/orb --type follow --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'
    And orb-cli is executed with args 'acceptlist add --url https://localhost:48426/services/orb/acceptlist --actor https://orb.domain1.com/services/orb --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'

  @orb_cli_did
  Scenario: test create and update did doc using cli
    # domain2 server follows domain1 server
    When user create "follower" activity with outbox-url "https://localhost:48426/services/orb/outbox" actor "https://orb.domain2.com/services/orb" to "https://orb.domain1.com/services/orb" action "Follow"
    # domain1 invites domain2 to be a witness
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When Create keys in kms
    When Orb DID is created through cli
    Then check cli created valid DID
    Then Orb DID is resolved through cli
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
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "InviteWitness"
    Then we wait 3 seconds
    When user create "witness" activity with outbox-url "https://localhost:48326/services/orb/outbox" actor "https://orb.domain1.com/services/orb" to "https://orb.domain2.com/services/orb" action "Undo"

  @orb_cli_acceptlist
  Scenario: test accept list management using cli
    # Add actors to the 'follow' accept list.
    When orb-cli is executed with args 'acceptlist add --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domainx.com/services/orb --actor https://orb.domainy.com/services/orb --type follow --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'
    # Add actors to the 'invite-witness' accept list.
    Then orb-cli is executed with args 'acceptlist add --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domainz.com/services/orb --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'

    When orb-cli is executed with args 'acceptlist get --url https://localhost:48326/services/orb/acceptlist --type follow --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token READ_TOKEN'
    Then the JSON path "url" of the response contains "https://orb.domainx.com/services/orb"
    Then the JSON path "url" of the response contains "https://orb.domainy.com/services/orb"

    And orb-cli is executed with args 'acceptlist get --url https://localhost:48326/services/orb/acceptlist --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token READ_TOKEN'
    Then the JSON path "url" of the response contains "https://orb.domainz.com/services/orb"

    And orb-cli is executed with args 'acceptlist get --url https://localhost:48326/services/orb/acceptlist --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token READ_TOKEN'
    Then the JSON path '#(type="follow").url' of the response contains "https://orb.domainx.com/services/orb"
    And the JSON path '#(type="follow").url' of the response contains "https://orb.domainx.com/services/orb"
    And the JSON path '#(type="invite-witness").url' of the response contains "https://orb.domainz.com/services/orb"

    # Remove actors from the 'follow' accept list.
    When orb-cli is executed with args 'acceptlist remove --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domainx.com/services/orb --actor https://orb.domainy.com/services/orb --type follow --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'
    # Remove actors from the 'invite-witness' accept list.
    Then orb-cli is executed with args 'acceptlist remove --url https://localhost:48326/services/orb/acceptlist --actor https://orb.domainz.com/services/orb --type invite-witness --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token ADMIN_TOKEN'

    And orb-cli is executed with args 'acceptlist get --url https://localhost:48326/services/orb/acceptlist --tls-cacerts fixtures/keys/tls/ec-cacert.pem --auth-token READ_TOKEN'
    Then the JSON path '#(type="follow").url' of the response does not contain "https://orb.domainx.com/services/orb"
    And the JSON path '#(type="follow").url' of the response does not contain "https://orb.domainx.com/services/orb"
    And the JSON path '#(type="invite-witness").url' of the response does not contain "https://orb.domainz.com/services/orb"
