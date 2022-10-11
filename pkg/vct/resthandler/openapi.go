/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

// swagger:parameters logGetReq
type logGetReq struct { //nolint: unused
}

// swagger:response logGetResp
type logGetResp struct { //nolint: unused
	Body string
}

// getLog swagger:route GET /log Log logGetReq
//
// Retrieves the current witness log.
//
// Responses:
//
//	200: logGetResp
func getLog() { //nolint: unused
}

// swagger:parameters logPostReq
type logPostReq struct { //nolint: unused
	// in: body
	Body string
}

// swagger:response logPostResp
type logPostResp struct { //nolint: unused
	Body string
}

// postLog swagger:route Post /log Log logPostReq
//
// Sets the current witness log.
//
// Responses:
//
//	200: logPostResp
func postLog() { //nolint: unused
}
