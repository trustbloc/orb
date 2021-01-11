/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import "fmt"

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}
