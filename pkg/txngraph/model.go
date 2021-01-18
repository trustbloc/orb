/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txngraph

// Node defines transaction information.
type Node struct {
	AnchorString   string            `json:"anchorString"`
	Namespace      string            `json:"namespace"`
	Version        uint64            `json:"version"`
	PreviousDidTxn map[string]string `json:"previousDidTransaction"`
}
