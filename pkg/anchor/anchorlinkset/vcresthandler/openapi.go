/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcresthandler

// swagger:parameters vcGetReq
type vcGetReq struct { // nolint: unused,deadcode
	// in: path
	ID string `json:"id"`
}

// swagger:response vcGetResp
type vcGetResp struct { // nolint: unused,deadcode
	Body string
}

// getVC swagger:route GET /vc/{id} VC vcGetReq
//
// Retrieves the current witness vc.
//
// Responses:
//        200: vcGetResp
func getVC() { // nolint: unused,deadcode
}
