/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/store/operation/unpublished"
)

// Sidetree holds global Sidetree configuration.
type Sidetree struct {
	MethodContext []string
	EnableBase    bool
	AnchorOrigins []string

	UnpublishedOpStore                      *unpublished.Store
	UnpublishedOperationStoreOperationTypes []operation.Type

	IncludeUnpublishedOperations bool
	IncludePublishedOperations   bool
}
