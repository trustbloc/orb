/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package metrics

// swagger:parameters metricsGetReq
type metricsGetReq struct { // nolint: unused,deadcode
}

// swagger:response metricsGetResp
type metricsGetResp struct { // nolint: unused,deadcode
	Body string
}

// getMetrics swagger:route GET /metrics System metricsGetReq
//
// Retrieves the current witness metrics.
//
// Responses:
//        200: metricsGetResp
func getMetrics() { // nolint: unused,deadcode
}
