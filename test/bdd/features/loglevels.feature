#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@loglevels
Feature: Log Levels
  Background: Setup
    Given host "orb.domain1.com" is mapped to "localhost:48326"
    And host "orb2.domain1.com" is mapped to "localhost:48526"
    And the authorization bearer token for "POST" requests to path "/loglevels" is set to "ADMIN_TOKEN"

  @loglevels_put_and_get
  Scenario: Tests the /loglevels endpoint
    When an HTTP GET is sent to "https://orb.domain1.com/loglevels"
    Then the response is saved to variable "originalLogLevels"

    When an HTTP POST is sent to "https://orb.domain1.com/loglevels" with content "xxx" of type "text/plain" and the returned status code is 400

    Given an HTTP POST is sent to "https://orb.domain1.com/loglevels" with content "test-module1=ERROR:test-module2=WARN:INFO" of type "text/plain"
    When an HTTP GET is sent to "https://orb.domain1.com/loglevels"
    Then the response contains ":INFO"
    And the response contains "test-module1=ERROR"
    And the response contains "test-module2=WARN"

    # Restore the log levels
    Given an HTTP POST is sent to "https://orb.domain1.com/loglevels" with content "${originalLogLevels}" of type "text/plain"
