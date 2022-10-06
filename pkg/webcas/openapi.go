/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webcas

// swagger:parameters casGetReq
type casGetReq struct { //nolint: unused
	// in: path
	ID string `json:"id"`
}

// swagger:response casGetResp
type casGetResp struct { //nolint: unused
	Body string
}

// handleGet swagger:route GET /cas/{id} CAS casGetReq
//
// Returns content stored in the Content Addressable Storage (CAS). The ID is either an IPFS CID or the hash of the content.
//
// Responses:
//
// 200: casGetResp
func casGetRequest() { //nolint: unused
}
