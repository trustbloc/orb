/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

// Sidetree holds global Sidetree configuration.
type Sidetree struct {
	MethodContext []string
	EnableBase    bool
	AnchorOrigins []string
}
