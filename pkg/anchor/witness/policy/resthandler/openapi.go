/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

// swagger:parameters policyGetReq
type policyGetReq struct { //nolint: unused
}

// swagger:response policyGetResp
type policyGetResp struct { //nolint: unused
	Body string
}

// getPolicy swagger:route GET /policy policy policyGetReq
//
// Retrieves the current witness policy.
//
// Responses:
//
//	200: policyGetResp
func getPolicy() { //nolint: unused
}

// swagger:parameters policyPostReq
type policyPostReq struct { //nolint: unused
	// in: body
	Body string
}

// swagger:response policyPostResp
type policyPostResp struct { //nolint: unused
	Body string
}

// postPolicy swagger:route POST /policy policy policyPostReq
//
// Retrieves the current witness policy.
//
// Responses:
//
//	200: policyPostResp
func postPolicy() { //nolint: unused
}
