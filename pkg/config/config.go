/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import "github.com/trustbloc/sidetree-core-go/pkg/api/operation"

// Sidetree holds global Sidetree configuration.
type Sidetree struct {
	MethodContext []string
	EnableBase    bool
	AnchorOrigins []string

	UpdateDocumentStoreEnabled bool
	UpdateDocumentStoreTypes   []operation.Type
}
