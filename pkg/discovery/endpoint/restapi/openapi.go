/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package restapi

// genericError model
//
// swagger:response genericError
type genericError struct { //nolint: unused
	// in: body
	Body ErrorResponse
}

// wellKnownReq model
//
// swagger:parameters wellKnownReq
type wellKnownReq struct{} //nolint: unused

// wellKnownResp model
//
// swagger:response wellKnownResp
type wellKnownResp struct { //nolint: unused
	// in: body
	Body *WellKnownResponse
}

// webFingerReq model
//
// swagger:parameters webFingerReq
type webFingerReq struct { //nolint: unused
	// in: query
	Resource string `json:"resource"`
}

// webFingerResp model
//
// swagger:response webFingerResp
type webFingerResp struct { //nolint: unused
	// in: body
	Body *JRD
}

// wellKnownDIDReq model
//
// swagger:parameters wellKnownDIDReq
type wellKnownDIDReq struct{} //nolint: unused

// wellKnownDIDResp model
//
// swagger:response wellKnownDIDResp
type wellKnownDIDResp struct { //nolint: unused
}

// wellKnownNodeInfoReq model
//
// swagger:parameters wellKnownNodeInfoReq
type wellKnownNodeInfoReq struct{} //nolint: unused

// wellKnownNodeInfoResp model
//
// swagger:response wellKnownNodeInfoResp
type wellKnownNodeInfoResp struct { //nolint: unused
	// in: body
	Body *JRD
}
