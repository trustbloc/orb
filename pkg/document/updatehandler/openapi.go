/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package updatehandler

// Request message
//
// swagger:parameters operationsReq
type operationsReq struct { //nolint: unused
	// in: body
	Body string
}

// Response message
//
// swagger:response operationsResp
type operationsResp struct { //nolint: unused
	Body string
}

// handlePost swagger:route POST /sidetree/v1/operations Sidetree operationsReq
//
// Posts a Sidetree operation.
//
// Consumes:
// - application/json
//
// Responses:
//
//	200: operationsResp
func operationsResponse() { //nolint: unused
}
