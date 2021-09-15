/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subject

import "github.com/hyperledger/aries-framework-go/pkg/doc/util"

// Payload defines orb anchor details.
// TODO: remove JSON tags?
type Payload struct {
	OperationCount  uint64            `json:"operationCount"`
	CoreIndex       string            `json:"coreIndex"`
	Attachments     []string          `json:"attachments"`
	Namespace       string            `json:"namespace"`
	Version         uint64            `json:"version"`
	AnchorOrigin    string            `json:"anchorOrigin"`
	Published       *util.TimeWrapper `json:"published,omitempty"`
	PreviousAnchors map[string]string `json:"previousAnchors,omitempty"`
}
