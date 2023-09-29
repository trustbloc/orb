/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/trustbloc/sidetree-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/operationparser"

	"github.com/trustbloc/orb/pkg/store/operation/unpublished"
)

// Sidetree holds global Sidetree configuration.
type Sidetree struct {
	MethodContext []string
	EnableBase    bool

	UnpublishedOpStore                      *unpublished.Store
	UnpublishedOperationStoreOperationTypes []operation.Type

	IncludeUnpublishedOperations bool
	IncludePublishedOperations   bool

	AllowedOriginsValidator operationparser.ObjectValidator
}
