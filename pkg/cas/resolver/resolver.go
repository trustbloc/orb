/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/store/cas"
)

const cidWithPossibleHintNumPartsWithDomainPort = 4

var logger = log.New("cas-resolver")

type httpClient interface {
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

// Resolver represents a resolver that can resolve data in a CAS based on a CID and WebCAS URL.
type Resolver struct {
	localCAS           casapi.Client
	ipfsReader         ipfsReader
	httpClient         httpClient
	webFingerURIScheme string
}

type ipfsReader interface {
	Read(address string) ([]byte, error)
}

// New returns a new Resolver.
func New(casClient casapi.Client, ipfsReader ipfsReader, httpClient httpClient) *Resolver {
	return &Resolver{
		localCAS:           casClient,
		ipfsReader:         ipfsReader,
		httpClient:         httpClient,
		webFingerURIScheme: "https",
	}
}

// Resolve does the following:
// 1. If data is provided (not nil), then it will be stored via the local CAS. That data passed in will then simply be
//    returned back to the caller.
// 2. If data is not provided (is nil), then the local CAS will be checked to see if it has data at the cid provided.
//    If it does, then it is returned. If it doesn't, and a webCASURL is provided, then the data will be retrieved by
//    querying the webCASURL. This data will then get stored in the local CAS.
//    Finally, the data is returned to the caller.
// In both cases above, the CID produced by the local CAS will be checked against the cid passed in to ensure they are
// the same.
func (h *Resolver) Resolve(webCASURL *url.URL, cidWithPossibleHint string, //nolint:gocyclo,cyclop
	data []byte) ([]byte, error) {
	if data != nil {
		err := h.storeLocallyAndVerifyCID(data, cidWithPossibleHint)
		if err != nil {
			return nil, fmt.Errorf("failure while storing the data in the local CAS: %w", err)
		}

		return data, nil
	}

	logger.Debugf("resolving webCasURL[%v] and cid[%s]", webCASURL, cidWithPossibleHint)

	cid := cidWithPossibleHint

	cidWithPossibleHintParts := strings.Split(cidWithPossibleHint, ":")
	if len(cidWithPossibleHintParts) > 1 {
		cid = cidWithPossibleHintParts[len(cidWithPossibleHintParts)-1]
	}

	// Ensure we have the data stored in the local CAS.
	dataFromLocal, err := h.localCAS.Read(cid)
	if err != nil { //nolint: nestif // Breaking this up seems worse than leaving the nested ifs
		if webCASURL != nil && webCASURL.String() != "" {
			if errors.Is(err, cas.ErrContentNotFound) {
				dataFromRemote, errGetAndStoreRemoteData := h.getAndStoreDataFromRemote(webCASURL, cid)
				if errGetAndStoreRemoteData != nil {
					return nil, fmt.Errorf("failure while getting and storing data from the remote "+
						"WebCAS endpoint: %w", errGetAndStoreRemoteData)
				}

				return dataFromRemote, nil
			}
		}

		if len(cidWithPossibleHintParts) > 1 {
			return h.resolveCIDWithHint(cidWithPossibleHintParts)
		}

		if h.ipfsReader != nil {
			// last resort - try ipfs if reader configured
			return h.getAndStoreDataFromIPFS(cid)
		}

		return nil, fmt.Errorf("failed to get data stored at %s from the local CAS: %w", cid, err)
	}

	return dataFromLocal, nil
}

func (h *Resolver) resolveCIDWithHint(cidWithPossibleHintParts []string) ([]byte, error) {
	var dataFromRemote []byte

	switch cidWithPossibleHintParts[0] {
	case "webcas":
		domain := cidWithPossibleHintParts[1]

		// If the domain in the hint contains a port, this will ensure it's included.
		if len(cidWithPossibleHintParts) == cidWithPossibleHintNumPartsWithDomainPort {
			domain = fmt.Sprintf("%s:%s", domain, cidWithPossibleHintParts[2])
		}

		cid := cidWithPossibleHintParts[len(cidWithPossibleHintParts)-1]

		webCASURL, err := h.getWebCASURLViaWebFinger(domain, cid)
		if err != nil {
			return nil, fmt.Errorf("failed to determine WebCAS URL via WebFinger: %w", err)
		}

		dataFromRemote, err = h.getAndStoreDataFromRemote(webCASURL, cid)
		if err != nil {
			return nil, fmt.Errorf("failure while getting and storing data from the remote "+
				"WebCAS endpoint: %w", err)
		}

		logger.Debugf("successfully retrieved data for cid[%s] from webcas domain[%s]", cid, domain)

	case "ipfs":
		var err error

		cid := cidWithPossibleHintParts[1]

		if h.ipfsReader == nil {
			return nil, fmt.Errorf("ipfs reader is not supported")
		}

		dataFromRemote, err = h.getAndStoreDataFromIPFS(cid)
		if err != nil {
			return nil, fmt.Errorf("failure while getting and storing data from ipfs for cid with ipfs hint: %w", err)
		}

		logger.Debugf("successfully retrieved data for cid[%s] from ipfs", cid)

	default:
		return nil, fmt.Errorf("hint '%s' not supported", cidWithPossibleHintParts[0])
	}

	return dataFromRemote, nil
}

func (h *Resolver) getAndStoreDataFromRemote(webCASEndpoint *url.URL, cid string) ([]byte, error) {
	resp, err := h.httpClient.Get(context.Background(), transport.NewRequest(webCASEndpoint,
		transport.WithHeader(transport.AcceptHeader, transport.LDPlusJSONContentType)))
	if err != nil {
		return nil, fmt.Errorf("failed to execute GET call on %s: %w", webCASEndpoint.String(), err)
	}

	defer func() {
		errClose := resp.Body.Close()
		if errClose != nil {
			logger.Errorf("failed to close response body from WebCAS endpoint: %s", errClose.Error())
		}
	}()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body from remote WebCAS endpoint: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		errStoreLocallyAndVerifyCID := h.storeLocallyAndVerifyCID(responseBody, cid)
		if errStoreLocallyAndVerifyCID != nil {
			return nil, fmt.Errorf("failure while storing data retrieved from the remote "+
				"WebCAS endpoint locally: %w", errStoreLocallyAndVerifyCID)
		}
	} else {
		return nil, fmt.Errorf("failed to retrieve data from %s. "+
			"Response status code: %d. Response body: %s", webCASEndpoint.String(), resp.StatusCode,
			string(responseBody))
	}

	return responseBody, nil
}

func (h *Resolver) getAndStoreDataFromIPFS(cid string) ([]byte, error) {
	resp, err := h.ipfsReader.Read(cid)
	if err != nil {
		return nil, fmt.Errorf("failed to read cid[%s] from ipfs: %w", cid, err)
	}

	err = h.storeLocallyAndVerifyCID(resp, cid)
	if err != nil {
		return nil, fmt.Errorf("failure while storing data retrieved from the ipfs: %w",
			err)
	}

	return resp, nil
}

func (h *Resolver) storeLocallyAndVerifyCID(data []byte, cidFromOriginalRequest string) error {
	newCIDFromLocalCAS, err := h.localCAS.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to CAS "+
			"(and calculate CID in the process of doing so): %w", err)
	}

	logger.Debugf("Successfully stored data into CAS. Request CID [%s], "+
		"CID as determined by local store [%s], Data: %s", cidFromOriginalRequest, newCIDFromLocalCAS,
		string(data))

	if newCIDFromLocalCAS != cidFromOriginalRequest {
		return fmt.Errorf("successfully stored data into the local CAS, but the CID produced by "+
			"the local CAS (%s) does not match the CID from the original request (%s)",
			newCIDFromLocalCAS, cidFromOriginalRequest)
	}

	return nil
}

func (h *Resolver) getWebCASURLViaWebFinger(domain, cid string) (*url.URL, error) {
	u := fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s://%s/cas/%s",
		h.webFingerURIScheme, domain, h.webFingerURIScheme, domain, cid)

	webFingerURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("parse URL [%s]: %w", u, err)
	}

	resp, err := h.httpClient.Get(context.Background(), transport.NewRequest(webFingerURL,
		transport.WithHeader(transport.AcceptHeader, transport.LDPlusJSONContentType)))
	if err != nil {
		return nil, fmt.Errorf("failed to get response (URL: %s): %w", webFingerURL, err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Errorf("failed to close response body while getting WebCAS URL via WebFinger: %s", err.Error())
		}
	}()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received unexpected status code. URL [%s], "+
			"status code [%d], response body [%s]", webFingerURL, resp.StatusCode, string(respBytes))
	}

	webFingerResponse := restapi.WebFingerResponse{}

	err = json.Unmarshal(respBytes, &webFingerResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal WebFinger response: %w", err)
	}

	var webCASURLFromWebFinger string

	for _, link := range webFingerResponse.Links {
		if link.Rel == "working-copy" {
			webCASURLFromWebFinger = link.Href

			break
		}
	}

	webCASURL, err := url.Parse(webCASURLFromWebFinger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse webcas URL: %w", err)
	}

	return webCASURL, nil
}
