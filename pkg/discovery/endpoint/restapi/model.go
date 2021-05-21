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
	Type string `json:"type,omitempty"`
	Href string `json:"href,omitempty"`
}

// RawDoc did document.
type RawDoc struct {
	Context              string               `json:"@context"`
	ID                   string               `json:"id"`
	VerificationMethod   []verificationMethod `json:"verificationMethod"`
	Authentication       []string             `json:"authentication"`
	AssertionMethod      []string             `json:"assertionMethod"`
	CapabilityDelegation []string             `json:"capabilityDelegation"`
	CapabilityInvocation []string             `json:"capabilityInvocation"`
}

type verificationMethod struct {
	ID              string `json:"id"`
	Controller      string `json:"controller"`
	Type            string `json:"type"`
	PublicKeyBase58 string `json:"publicKeyBase58"`
}
