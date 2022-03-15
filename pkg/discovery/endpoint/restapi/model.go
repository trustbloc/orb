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

// JRD is a JSON Resource Descriptor as defined in https://datatracker.ietf.org/doc/html/rfc6415#appendix-A
// and https://datatracker.ietf.org/doc/html/rfc7033#section-4.4.
type JRD struct {
	Subject    string                 `json:"subject,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Links      []Link                 `json:"links,omitempty"`
}

// Link is a link in a JRD.
// Note that while the host-meta and WebFinger endpoints both use this, only host-meta supports the Template field.
type Link struct {
	Rel      string `json:"rel,omitempty"`
	Type     string `json:"type,omitempty"`
	Href     string `json:"href,omitempty"`
	Template string `json:"template,omitempty"`
}
