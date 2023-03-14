/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package loglevels

// Request message
//
// swagger:parameters loglevelsPostReq
type loglevelsPostReq struct { //nolint: unused
	// in: body
	Body string
}

// Response message
//
// swagger:response loglevelsPostResp
type loglevelsPostResp struct { //nolint: unused
	Body string
}

// handlePost swagger:route POST /loglevels System loglevelsPostReq
//
// Updates the logging levels.
//
// Consumes:
// - text/plain
//
// Produces:
// - text/plain
//
// Responses:
//
//	200: loglevelsPostResp
func loglevelsPostRequest() { //nolint: unused
}

// swagger:parameters loglevelsGetReq
type loglevelsGetReq struct { //nolint: unused
}

// swagger:response loglevelsGetResp
type loglevelsGetResp struct { //nolint: unused
	// in: body
	Body string
}

// loglevelsGetRequest swagger:route GET /loglevels System loglevelsGetReq
//
// Retrieves the logging levels.
//
// Produces:
// - text/plain
//
// Responses:
//
//	200: loglevelsGetResp
func loglevelsGetRequest() { //nolint: unused
}
