/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	Body string
}

// nodeInfoReq model
//
// swagger:parameters nodeInfoReq
type nodeInfoReq struct{} // nolint: unused,deadcode

// nodeInfoResp model
//
// swagger:response NodeInfo
type nodeInfoResp struct { // nolint: unused,deadcode
	// in: body
	Body *NodeInfo
}
