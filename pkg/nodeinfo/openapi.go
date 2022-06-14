/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package nodeinfo

// nodeInfo20Req model
//
// swagger:parameters nodeInfo20Req
type nodeInfo20Req struct{} // nolint: unused,deadcode

// nodeInfo20Resp model
//
// swagger:response nodeInfo20Resp
type nodeInfo20Resp struct { // nolint: unused,deadcode
	// in: body
	Body *NodeInfo
}

//nolint:lll
// handle swagger:route Get /nodeinfo/2.0 System nodeInfo20Req
//
// The NodeInfo endpoints provide general information about an Orb server, including the version, the number of posts (Create activities) and the number of comments (Like activities). This endpoint returns a version 2.0 response.
//
// Responses:
//        200: nodeInfo20Resp
func (h *Handler) nodeInfo20GetReq() { // nolint: unused
}

// nodeInfo21Req model
//
// swagger:parameters nodeInfo21Req
type nodeInfo21Req struct{} // nolint: unused,deadcode

// nodeInfo21Resp model
//
// swagger:response nodeInfo21Resp
type nodeInfo21Resp struct { // nolint: unused,deadcode
	// in: body
	Body *NodeInfo
}

//nolint:lll
// handle swagger:route Get /nodeinfo/2.1 System nodeInfo21Req
//
// The NodeInfo endpoints provide general information about an Orb server, including the version, the number of posts (Create activities) and the number of comments (Like activities). This endpoint returns a version 2.1 response.
//
// Responses:
//        200: nodeInfo21Resp
func (h *Handler) nodeInfo21GetReq() { // nolint: unused
}
