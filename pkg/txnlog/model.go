/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnlog

// Info describes transaction.
type Info struct {
	AnchorString        string `json:"anchorString"`
	Namespace           string `json:"namespace"`
	ProtocolGenesisTime uint64 `json:"protocolGenesisTime"`
}
