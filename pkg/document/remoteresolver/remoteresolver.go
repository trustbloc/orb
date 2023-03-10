/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package remoteresolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/document"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
)

var logger = log.New("remote-resolver")

const (
	didLDJson = "application/did+ld+json"
)

// Resolver resolves document from remote server.
type Resolver struct {
	httpClient httpClient
}

type httpClient interface {
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

// New create new remote resolver.
func New(httpClient httpClient) *Resolver {
	return &Resolver{
		httpClient: httpClient,
	}
}

// ResolveDocumentFromResolutionEndpoints resolved document from resolution endpoints.
func (rr *Resolver) ResolveDocumentFromResolutionEndpoints(id string, endpoints []string) (*document.ResolutionResult, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("must provide at least one remote resolver endpoint in order to retrieve data")
	}

	var errMsgs []string

	for _, endpoint := range endpoints {
		rr, err := rr.resolveDocumentFromEndpoint(id, endpoint)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())

			continue
		}

		return rr, nil
	}

	return nil, fmt.Errorf("%s", errMsgs)
}

func (rr *Resolver) resolveDocumentFromEndpoint(id, endpoint string) (*document.ResolutionResult, error) {
	reqURL := fmt.Sprintf("%s/%s", endpoint, id)

	responseBytes, err := rr.send(reqURL)
	if err != nil {
		return nil, fmt.Errorf("remote request[%s]: %w", reqURL, err)
	}

	var respObj document.ResolutionResult

	err = json.Unmarshal(responseBytes, &respObj)
	if err != nil {
		return nil, fmt.Errorf("remote request[%s]: failed to unmarshal resolution result[%s]: %w",
			reqURL, string(responseBytes), err)
	}

	return &respObj, nil
}

// resolveDID makes DID resolution via HTTP.
func (rr *Resolver) send(uri string) ([]byte, error) {
	req, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request URL[%s]: %w", uri, err)
	}

	resp, err := rr.httpClient.Get(context.Background(), transport.NewRequest(req,
		transport.WithHeader(transport.AcceptHeader, didLDJson)))
	if err != nil {
		return nil, fmt.Errorf("failed to execute GET call on %s: %w", req.String(), err)
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.CloseResponseBodyError(logger, errClose)
		}
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body for request[%s]: %w", req.String(), err)
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-type"), didLDJson) {
		return responseBody, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("data not found for request[%s]. Response status code: %d. Response body: %s",
			req.String(), resp.StatusCode, string(responseBody))
	}

	return nil, fmt.Errorf("failed to retrieve data for request[%s]. Response status code: %d. Content-type: %s. Response body: %s",
		req.String(), resp.StatusCode, resp.Header.Get("Content-type"), string(responseBody))
}
