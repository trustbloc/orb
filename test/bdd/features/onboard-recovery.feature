#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@orb-onboarding-and-recovery
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain5IRI" is assigned the value "https://orb.domain5.com/services/orb"

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And domain "orb.domain5.com" is mapped to "localhost:49026"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/policy" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/cas" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/vc" is set to "READ_TOKEN"

    # domain1 adds domain2 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain1AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain2IRI}"]},{"type":"invite-witness","add":["${domain2IRI}"]}]'
    When an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${domain1AcceptList}" of type "application/json"

    # domain2 adds domain1 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain1IRI}"]},{"type":"invite-witness","add":["${domain1IRI}"]}]'
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${domain2AcceptList}" of type "application/json"

    # domain2 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain2IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # set witness policy for domain1
    When an HTTP POST is sent to "https://orb.domain1.com/policy" with content "MinPercent(100,batch) AND MinPercent(50,system)" of type "text/plain"

    Then we wait 5 seconds

  @all
  @orb_domain_onboarding_recovery
  Scenario: Domain onboarding and recovery
    # Create and update a bunch of DIDs.
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents that were created with public key ID "newkey_1_1" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_1"
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_1_2" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_2"
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_1_3" using 10 concurrent requests

    # Don't wait for the updates to finish. On-board domain5 immediately and then verify them on domain5.

    # Onboard domain5 by asking to follow domain1 and domain2:
    # --- domain1 and domain2 add domain5 to the 'follow' and 'invite-witness' accept lists.
    Given variable "acceptList" is assigned the JSON value '[{"type":"follow","add":["${domain5IRI}"]},{"type":"invite-witness","add":["${domain5IRI}"]}]'
    When an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    # --- domain5 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain5 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain1 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain2 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # The synchronization process should kick in for domain5, i.e. domain5 will read all missed 'Create' and 'Announce'
    # activities from domain1 and domain2's outbox to figure out which events were missed (which should be all of them)
    # and then process the missed anchor events.
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_3"

    # Now stop domain5 for a while and populate domain1 & domain2 with more creates/updates.
    Then container "orb-domain5" is stopped

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents that were created with public key ID "newkey_2_1" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_2_1"

    Then container "orb-domain5" is started

    # Send a bunch more updates to the DIDs that were created while domain5 was down. Domain5 will need to process the new 'updates'
    # and also sync up with all of the previous operations.
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_2_2" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_2_2"
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_2_3" using 10 concurrent requests

    # Resolve the DIDs from domain5, which should have synced up with the other domains.
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_2_3"

    # Create a bunch of DIDs on domain5 and make sure they're available on domain1 and domain2.
    When client sends request to "https://orb.domain5.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created
