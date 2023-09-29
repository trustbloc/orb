/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolvehandler

import (
	"github.com/trustbloc/sidetree-go/pkg/document"
)

// swagger:parameters identifiersReq
type identifiersReq struct { //nolint: unused
	// In: path
	ID string `json:"id"`
}

// swagger:response identifiersResp
type identifiersResp struct { //nolint: unused
	// in: body
	Body document.ResolutionResult
}

// identifiersRequest swagger:route GET /sidetree/v1/identifiers/{id} Sidetree identifiersReq
//
// A DID document is retrieved using the /sidetree/v1/identifiers endpoint.
//
// Produces:
// - application/json
//
// Responses:
//
//	200: identifiersResp
func identifiersRequest() { //nolint: unused
}
