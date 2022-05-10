#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@local_cas
@orb-onboarding-and-recovery
Feature:
  Background: Setup
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain5IRI" is assigned the value "https://orb.domain5.com/services/orb"

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb2.domain1.com" is mapped to "localhost:48526"
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
    And the authorization bearer token for "POST" requests to path "/log" is set to "ADMIN_TOKEN"

    # set up logs for domains
    When an HTTP POST is sent to "https://orb.domain1.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"
    When an HTTP POST is sent to "https://orb.domain2.com/log" with content "" of type "text/plain"
    When an HTTP POST is sent to "https://orb.domain5.com/log" with content "" of type "text/plain"

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
    When an HTTP POST is sent to "https://orb.domain1.com/policy" with content "OutOf(1,system)" of type "text/plain"
    # set witness policy for domain2
    When an HTTP POST is sent to "https://orb.domain2.com/policy" with content "OutOf(1,system)" of type "text/plain"

    Then we wait 5 seconds

  @orb_domain_onboarding_recovery
  Scenario: Domain onboarding and recovery
    # Create and update a bunch of DIDs in the background.
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 200 DID documents using 3 concurrent requests in the background
    Then we wait 3 seconds

    # Stop an instance in domain2 (orb-domain2.backend) while DIDs are still being created to ensure that the pending operations in orb-domain2's queue are reposted
    # to the AMQP queue so that they are processed by the other instance (orb1-domain2.backend).
    Then container "orb-domain2.backend" is stopped
    And we wait up to "2m" for 200 DID documents to be created
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created
    Then container "orb-domain2.backend" is started

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents that were created with public key ID "newkey_1_1" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_1"
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_1_2" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_2"
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents again with public key ID "newkey_1_3" using 10 concurrent requests

    # Don't wait for the updates to finish. On-board domain5 immediately and then verify them on domain5.

    # Onboard domain5 by asking to follow domain1 and domain2:
    When an HTTP POST is sent to "https://orb.domain5.com/policy" with content "OutOf(1,system)" of type "text/plain"
    # --- domain1 and domain2 add domain5 to the 'follow' and 'invite-witness' accept lists.
    Given variable "acceptList" is assigned the JSON value '[{"type":"follow","add":["${domain5IRI}"]},{"type":"invite-witness","add":["${domain5IRI}"]}]'
    Then an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    Then an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    # --- domain5 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain5 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain1 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain1 invites domain5 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1IRI}","to":"${domain5IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain2 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain2 invites domain5 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain2IRI}","to":"${domain5IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # The synchronization process should kick in for domain5, i.e. domain5 will read all missed 'Create' and 'Announce'
    # activities from domain1 and domain2's outbox to figure out which events were missed (which should be all of them)
    # and then process the missed anchor events.
    # Create some new DIDs on domain5 while recovery is happening.
    When client sends request to "https://orb.domain5.com/sidetree/v1/operations" to create 50 DID documents using 5 concurrent requests
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers" to verify the DID documents that were created
    And client sends request to "https://orb.domain5.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_1_3"

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

    # Test AMQP service restart:
    # Create a bunch of DIDs on domain1, domain2, and domain5 in the background.
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations,https://orb.domain5.com/sidetree/v1/operations" to create 200 DID documents using 3 concurrent requests in the background
    # Wait for domain5 to add some DID operations to it's queue.
    And we wait 3 seconds
    # Restart the AMQP server in domain5 while DIDs are still being created to ensure that pending operations
    # in domain5's queue are recovered after the AMQP server comes online.
    Then container "orb.mq.domain5.com" is restarted
    And we wait up to "5m" for 200 DID documents to be created
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers" to verify the DID documents that were created

  @orb_domain_backup_and_restore
  Scenario: Backup and restore a domain
    # Onboard domain5 by asking to follow domain1 and domain2:
    When an HTTP POST is sent to "https://orb.domain5.com/policy" with content "MinPercent(100,batch) AND MinPercent(50,system)" of type "text/plain"
    # --- domain1 and domain2 add domain5 to the 'follow' and 'invite-witness' accept lists.
    Given variable "acceptList" is assigned the JSON value '[{"type":"follow","add":["${domain5IRI}"]},{"type":"invite-witness","add":["${domain5IRI}"]}]'
    Then an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    Then an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${acceptList}" of type "application/json"
    # --- domain5 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain5IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain5 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain5 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain5IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain5.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain1 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain1 invites domain5 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1IRI}","to":"${domain5IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"
    # --- domain2 server follows domain5 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain5IRI}","object":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"
    # --- domain2 invites domain5 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain2IRI}","to":"${domain5IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain5IRI}"}'
    Then an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # Take a backup of the domain5 database.
    When command "mongodump --out ./fixtures/mongodbbackup --host localhost --port 28017" is executed

    # Create some DIDs on domain5, domain1, domain2.
    When client sends request to "https://orb.domain5.com/sidetree/v1/operations,https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers,https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created

    Then we wait 5 seconds

    # Update the DIDs on domain5, domain1, domain2.
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to update the DID documents that were created with public key ID "newkey_3_1" using 10 concurrent requests
    Then client sends request to "https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_3_1"

    Then container "orb-domain5" is stopped

    # Create some DIDs on domain1 and domain2 while domain5 is down.
    Then client sends request to "https://orb.domain1.com/sidetree/v1/operations,https://orb.domain2.com/sidetree/v1/operations" to create 50 DID documents using 10 concurrent requests

    # Wipe out the database on domain5 by recreating the mongodb container.
    And container "mongodb.domain5.com" is recreated

    Then we wait 5 seconds

    # Restore the database from backup. Note that the DB will NOT contain the AnchorEvents, Sidetree files,
    # or Sidetree operations that were created after the backup.
    Then command "mongorestore ./fixtures/mongodbbackup --host localhost --port 28017" is executed
    And command "rm -rf ./fixtures/mongodbbackup" is executed

    # Start domain5 and wait a bit for the synchronization process to kick in.
    Then container "orb-domain5" is started

    Then we wait 15 seconds

    # Ensure that domain5 has retrieved the anchor files (that were created after the backup) from alternate sources.
    Then client sends request to "https://orb.domain5.com/sidetree/v1/identifiers,https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were updated with key "newkey_3_1"
    And client sends request to "https://orb.domain5.com/sidetree/v1/identifiers,https://orb.domain1.com/sidetree/v1/identifiers,https://orb.domain2.com/sidetree/v1/identifiers" to verify the DID documents that were created
