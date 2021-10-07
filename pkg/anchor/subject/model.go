/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subject

import (
	"time"
)

// Payload defines orb anchor details.
type Payload struct {
	OperationCount  uint64
	CoreIndex       string
	Attachments     []string
	Namespace       string
	Version         uint64
	AnchorOrigin    string
	Published       *time.Time
	PreviousAnchors map[string]string
}
