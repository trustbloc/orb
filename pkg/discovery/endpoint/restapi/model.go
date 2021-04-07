/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restapi

// ErrorResponse to send error message in the response.
type ErrorResponse struct {
	Message string `json:"errMessage,omitempty"`
}

// WellKnownResponse well known response.
type WellKnownResponse struct {
	ResolutionEndpoint string `json:"resolutionEndpoint,omitempty"`
	OperationEndpoint  string `json:"operationEndpoint,omitempty"`
}

// WebFingerResponse web finger response.
type WebFingerResponse struct {
	Subject    string                 `json:"subject,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Links      []WebFingerLink        `json:"links,omitempty"`
}

// WebFingerLink web finger link.
type WebFingerLink struct {
	Rel  string `json:"rel,omitempty"`
	Href string `json:"href,omitempty"`
}
