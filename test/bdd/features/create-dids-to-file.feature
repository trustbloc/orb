#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

Feature:
  Background: Setup
    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"

    And the authorization bearer token for "POST" requests to path "/log" is set to "ADMIN_TOKEN"

    # set up logs for domains
    When an HTTP POST is sent to "https://orb.domain1.com/log" with content "http://orb.vct:8077/maple2020" of type "text/plain"
    When an HTTP POST is sent to "https://orb.domain2.com/log" with content "" of type "text/plain"

  @create_dids_to_file
  Scenario: Create DIDs and store them in a file. (Uses environment variables.)
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "${ORB_BACKUP_READ_TOKEN}"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "${ORB_BACKUP_WRITE_TOKEN}"

    Then client sends request to domains "${ORB_BACKUP_DID_DOMAINS}" to create "${ORB_BACKUP_NUM_DIDS}" DID documents using "${ORB_BACKUP_CONCURRENCY}" concurrent requests and a maximum of "${ORB_BACKUP_CREATE_ATTEMPTS}" attempts, storing the dids to file "${ORB_BACKUP_CREATED_DIDS_FILE}"

  @verify_created_dids_from_file
  Scenario: Verify the DIDs in the given file. (Uses environment variables.)
    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "${ORB_BACKUP_READ_TOKEN}"

    Then client sends request to domains "${ORB_BACKUP_DID_DOMAINS}" to verify the DID documents that were created from file "${ORB_BACKUP_CREATED_DIDS_FILE}" with a maximum of "${ORB_BACKUP_VERIFY_ATTEMPTS}" attempts

  @all
  @create_and_verify_dids_from_file
  Scenario: Create DIDs, store them in a file and verify the DIDs from the file.
    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"

    Given the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"

    # domain2 adds domain1 to its 'invite-witness' accept lists.
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"invite-witness","add":["${domain1IRI}"]}]'
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${domain2AcceptList}" of type "application/json"

    # domain1 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    Then client sends request to domains "https://orb.domain1.com" to create "50" DID documents using "5" concurrent requests and a maximum of "2" attempts, storing the dids to file "./fixtures/dids.txt"
    And client sends request to domains "https://orb.domain1.com" to verify the DID documents that were created from file "./fixtures/dids.txt" with a maximum of "25" attempts
