/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
)

// ClientVersion implements client version.
type ClientVersion struct {
	VersionStr string
	P          protocol.Protocol
	OpProvider protocol.OperationProvider
}

// Version returns the protocol parameters.
func (h *ClientVersion) Version() string {
	return h.VersionStr
}

// Protocol returns the protocol parameters.
func (h *ClientVersion) Protocol() protocol.Protocol {
	return h.P
}

// OperationProvider returns the operation provider.
func (h *ClientVersion) OperationProvider() protocol.OperationProvider {
	return h.OpProvider
}
