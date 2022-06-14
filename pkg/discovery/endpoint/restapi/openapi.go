/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

// genericError model
//
// swagger:response genericError
type genericError struct { // nolint: unused,deadcode
	// in: body
	Body ErrorResponse
}

// wellKnownReq model
//
// swagger:parameters wellKnownReq
type wellKnownReq struct{} // nolint: unused,deadcode

// wellKnownResp model
//
// swagger:response wellKnownResp
type wellKnownResp struct { // nolint: unused,deadcode
	// in: body
	Body *WellKnownResponse
}

// webFingerReq model
//
// swagger:parameters webFingerReq
type webFingerReq struct { // nolint: unused,deadcode
	// in: query
	Resource string `json:"resource"`
}

// webFingerResp model
//
// swagger:response webFingerResp
type webFingerResp struct { // nolint: unused,deadcode
	// in: body
	Body *JRD
}

// wellKnownDIDReq model
//
// swagger:parameters wellKnownDIDReq
type wellKnownDIDReq struct{} // nolint: unused,deadcode

// wellKnownDIDResp model
//
// swagger:response wellKnownDIDResp
type wellKnownDIDResp struct { // nolint: unused,deadcode
}

// wellKnownNodeInfoReq model
//
// swagger:parameters wellKnownNodeInfoReq
type wellKnownNodeInfoReq struct{} // nolint: unused,deadcode

// wellKnownNodeInfoResp model
//
// swagger:response wellKnownNodeInfoResp
type wellKnownNodeInfoResp struct { // nolint: unused,deadcode
	// in: body
	Body *JRD
}
