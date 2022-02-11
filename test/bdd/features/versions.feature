#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@did-versioning
Feature:
  Background: Setup
    Given host-meta document is uploaded to IPNS
    Given variable "domain1IRI" is assigned the value "https://orb.domain1.com/services/orb"
    And variable "domain2IRI" is assigned the value "https://orb.domain2.com/services/orb"
    And variable "domain3IRI" is assigned the value "https://orb.domain3.com/services/orb"

    Given domain "orb.domain1.com" is mapped to "localhost:48326"
    And domain "orb.domain2.com" is mapped to "localhost:48426"
    And domain "orb.domain3.com" is mapped to "localhost:48626"

    Given the authorization bearer token for "POST" requests to path "/services/orb/outbox" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/services/orb/acceptlist" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/services/orb" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/sidetree/v1/identifiers" is set to "READ_TOKEN"
    And the authorization bearer token for "POST" requests to path "/sidetree/v1/operations" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "POST" requests to path "/policy" is set to "ADMIN_TOKEN"
    And the authorization bearer token for "GET" requests to path "/cas" is set to "READ_TOKEN"
    And the authorization bearer token for "GET" requests to path "/vc" is set to "READ_TOKEN"

    # domain1 adds domain2 and domain3 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain1AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain2IRI}","${domain3IRI}"]},{"type":"invite-witness","add":["${domain2IRI}","${domain3IRI}"]}]'
    When an HTTP POST is sent to "${domain1IRI}/acceptlist" with content "${domain1AcceptList}" of type "application/json"

    # domain2 adds domain1 to its 'follow' and 'invite-witness' accept lists.
    Given variable "domain2AcceptList" is assigned the JSON value '[{"type":"follow","add":["${domain1IRI}"]},{"type":"invite-witness","add":["${domain1IRI}","${domain4IRI}"]}]'
    When an HTTP POST is sent to "${domain2IRI}/acceptlist" with content "${domain2AcceptList}" of type "application/json"

    When an HTTP GET is sent to "${domain1IRI}/acceptlist"
    Then the JSON path '#(type="follow").url' of the response contains "${domain2IRI}"
    Then the JSON path '#(type="follow").url' of the response contains "${domain3IRI}"
    Then the JSON path '#(type="invite-witness").url' of the response contains "${domain2IRI}"
    Then the JSON path '#(type="invite-witness").url' of the response contains "${domain3IRI}"

    # domain2 server follows domain1 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain2IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 server follows domain2 server
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain1IRI}","to":"${domain2IRI}","object":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain3 server follows domain1 server. Domain3 needs to be a follower of domain1 so that HTTP signature validation succeeds when
    # the /cas endpoint is invoked on domain1 (since only followers and witnesses are authorized).
    And variable "followActivity" is assigned the JSON value '{"@context":"https://www.w3.org/ns/activitystreams","type":"Follow","actor":"${domain3IRI}","to":"${domain1IRI}","object":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${followActivity}" of type "application/json"

    # domain1 invites domain2 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain1IRI}","to":"${domain2IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain2IRI}"}'
    When an HTTP POST is sent to "https://orb.domain1.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain2 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain2IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain2.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # domain3 invites domain1 to be a witness
    And variable "inviteWitnessActivity" is assigned the JSON value '{"@context":["https://www.w3.org/ns/activitystreams","https://w3id.org/activityanchors/v1"],"type":"Invite","actor":"${domain3IRI}","to":"${domain1IRI}","object":"https://w3id.org/activityanchors#AnchorWitness","target":"${domain1IRI}"}'
    When an HTTP POST is sent to "https://orb.domain3.com/services/orb/outbox" with content "${inviteWitnessActivity}" of type "application/json"

    # set witness policy for domain1
    When an HTTP POST is sent to "https://orb.domain1.com/policy" with content "MinPercent(100,batch) AND MinPercent(50,system)" of type "text/plain"

    Then we wait 3 seconds

  @sidetree_protocol_versions
  Scenario: upgrade sidetree protocol version

    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to create DID document
    Then check success response contains "#interimDID"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with equivalent did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "canonicalId"

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "canonicalId"

    # version one protocol can handle adding 5 keys at once (it is withing maximum operation size)
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add 5 public keys to DID document
    Then check for request success

    # version one protocol cannot handle adding 7 keys at once (it is withing maximum operation size)
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add 7 public keys to DID document
    Then check error response contains "exceeds maximum delta size"

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "key-5"

    When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "key-4"

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "key-3"

    And we wait 2 seconds

    Then set environment variable "SIDETREE_VERSIONS" to the value "1.0,test"

    Then container "orb-domain1" is recreated
    And container "orb2-domain1" is recreated
    # And container "orb-domain2" is recreated
    And container "orb-domain3" is recreated

    And we wait 15 seconds

    # update document
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add public key with ID "testKey" to DID document
    Then check for request success

    When client sends request to "https://orb.domain1.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "testKey"

    When client sends request to "https://orb.domain2.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response does NOT contain "testKey"

    When client sends request to "https://orb.domain3.com/sidetree/v1/identifiers" to resolve DID document with canonical did
    Then check success response contains "testKey"

    # test version of protocol cannot handle adding 5 keys at once (exceeds max operation/delta size)
    When client sends request to "https://orb.domain1.com/sidetree/v1/operations" to add 5 public keys to DID document
    Then check error response contains "exceeds maximum operation size"


