/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

const (
	activityPubProtocol = "activitypub"
	orbRepository       = "https://github.com/trustbloc/orb"
)

// Version specified the version of the NodeInfo data.
type Version = string

const (
	// V2_0 is NodeInfo version 2.0 (http://nodeinfo.diaspora.software/ns/schema/2.0#).
	V2_0 Version = "2.0"

	// V2_1 is NodeInfo version 2.1 (http://nodeinfo.diaspora.software/ns/schema/2.1#).
	V2_1 Version = "2.1"
)

// NodeInfo contains NodeInfo data.
type NodeInfo struct {
	Version           string                 `json:"version"`
	Software          Software               `json:"software"`
	Protocols         []string               `json:"protocols"`
	Services          Services               `json:"services"`
	OpenRegistrations bool                   `json:"openRegistrations"`
	Usage             Usage                  `json:"usage"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// Software contains information about the Orb application, including version.
type Software struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Repository string `json:"repository,omitempty"`
}

// Services contains services. (Currently Orb does not use this object.)
type Services struct {
	Inbound  []string `json:"inbound"`
	Outbound []string `json:"outbound"`
}

// Usage contains usage statistics, including the number of 'Create' and 'Like' activities were issued by this node.
type Usage struct {
	Users         Users `json:"users"`
	LocalPosts    int   `json:"localPosts"`
	LocalComments int   `json:"localComments"`
}

// Users contains the number of users. (Currently always 1.)
type Users struct {
	Total int `json:"total"`
}
