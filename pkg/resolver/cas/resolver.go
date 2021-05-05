/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	"github.com/trustbloc/orb/pkg/store/cas"
)

var logger = log.New("cas-resolver")

// Resolver represents a resolver that can resolve data in a CAS based on a CID and WebCAS URL.
type Resolver struct {
	localCAS   casapi.Client
	httpClient *http.Client
}

// New returns a new Resolver.
func New(casClient casapi.Client, httpClient *http.Client) *Resolver {
	return &Resolver{
		localCAS:   casClient,
		httpClient: httpClient,
	}
}

// Resolve does the following:
// 1. If data is provided (not nil), then it will be stored via the local CAS. That data passed in will then simply be
//    returned back to the caller.
// 2. If data is not provided (is nil), then the local CAS will be checked to see if it has data at the cid provided.
//    If it does, then it is returned. If it doesn't, then the data will be retrieved by querying the webCASURL
//    passed in. This data will then get stored in the local CAS. Finally, the data is returned to the caller.
// In both cases above, the CID produced by the local CAS will be checked against the cid passed in to ensure they are
// the same.
func (h *Resolver) Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, error) {
	if data != nil {
		err := h.storeLocallyAndVerifyCID(data, cid)
		if err != nil {
			return nil, fmt.Errorf("failure while storing the data in the local CAS: %w", err)
		}

		return data, nil
	}

	// Ensure we have the data stored in the local CAS.
	dataFromLocal, err := h.localCAS.Read(cid)
	if err != nil {
		if errors.Is(err, cas.ErrContentNotFound) {
			dataFromRemote, errGetAndStoreRemoteData := h.getAndDataFromRemote(webCASURL, cid)
			if errGetAndStoreRemoteData != nil {
				return nil, fmt.Errorf("failure while getting and storing data from the remote "+
					"WebCAS endpoint: %w", errGetAndStoreRemoteData)
			}

			return dataFromRemote, nil
		}

		return nil, fmt.Errorf("unexpected failure while checking local CAS for data stored at %s: %w",
			cid, err)
	}

	return dataFromLocal, nil
}

func (h *Resolver) getAndDataFromRemote(webCASEndpoint *url.URL, cid string) ([]byte, error) {
	resp, err := h.httpClient.Get(webCASEndpoint.String())
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
			"Response status code: %d. Response body: %s", webCASEndpoint, resp.StatusCode, string(responseBody))
	}

	return responseBody, nil
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
