/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/multihash"
	webfingerclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	httpPrefix  = "http://"
	httpsPrefix = "https://"
	ipfsPrefix  = "ipfs://"

	cidWithPossibleHintNumPartsWithDomainPort = 4
)

const logModule = "cas-resolver"

var logger = log.NewStructured(logModule)

type httpClient interface {
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

type metricsProvider interface {
	CASResolveTime(value time.Duration)
}

// Resolver represents a resolver that can resolve data in a CAS based on a CID (with possible hint) and a WebCAS URL.
type Resolver struct {
	localCAS       extendedcasclient.Client
	ipfsReader     ipfsReader
	webCASResolver WebCASResolver
	metrics        metricsProvider
	hl             *hashlink.HashLink
}

type ipfsReader interface {
	Read(address string) ([]byte, error)
}

// New returns a new Resolver.
// ipfsReader is optional. If not provided (is nil), CIDs with IPFS hints won't be resolvable.
func New(casClient extendedcasclient.Client, ipfsReader ipfsReader, webCASResolver WebCASResolver,
	metrics metricsProvider) *Resolver {
	return &Resolver{
		localCAS:       casClient,
		ipfsReader:     ipfsReader,
		webCASResolver: webCASResolver,
		metrics:        metrics,
		hl:             hashlink.New(),
	}
}

// Resolve does the following:
// 1. If data is provided (not nil), then it will be stored via the local CAS. That data passed in will then simply be
//    returned back to the caller, along with the hashlink of the stored data.
// 2. If data is not provided (is nil), then the local CAS will be checked to see if it has data at the cid provided.
//    If it does, then it is returned. If it doesn't, and a webCASURL is provided, then the data will be retrieved by
//    querying the webCASURL. This data will then get stored in the local CAS.
//    Finally, the data is returned to the caller, along with the hashlink of the stored data.
// In both cases above, the CID produced by the local CAS will be checked against the cid passed in to ensure they are
// the same.
func (h *Resolver) Resolve(_ *url.URL, hashWithPossibleHint string, data []byte) ([]byte, string, error) { //nolint:gocyclo,cyclop,lll,funlen
	startTime := time.Now()

	defer func() { h.metrics.CASResolveTime(time.Since(startTime)) }()

	resourceHash, domain, links, err := h.getResourceHashWithPossibleDomainAndLinks(hashWithPossibleHint)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get resource hash from[%s]: %w", hashWithPossibleHint, err)
	}

	if data != nil {
		localHL, e := h.storeLocallyAndVerifyHash(data, resourceHash)
		if e != nil {
			return nil, "", fmt.Errorf("failed to store the data in the local CAS: %w", e)
		}

		return data, localHL, nil
	}

	logger.Debug("Resolving...", log.WithKey(hashWithPossibleHint), log.WithHash(resourceHash),
		log.WithDomain(domain), log.WithLinks(links...))

	casLinks, ipfsLinks := separateLinks(links)

	if h.localCAS.GetPrimaryWriterType() == "ipfs" && len(ipfsLinks) > 0 {
		cid := ipfsLinks[0][len(ipfsPrefix):]

		data, e := h.localCAS.Read(cid)
		if e != nil {
			return nil, "", fmt.Errorf("read from IPFS: %w", e)
		}

		return data, "", nil
	}

	// Ensure we have the data stored in the local CAS.
	dataFromLocal, err := h.localCAS.Read(resourceHash)
	if err != nil { //nolint: nestif // Breaking this up seems worse than leaving the nested ifs
		if errors.Is(err, orberrors.ErrContentNotFound) {
			if len(casLinks) > 0 {
				dataFromRemote, localHL, errGetAndStoreRemoteData := h.getAndStoreDataFromWebCASEndpoints(casLinks, resourceHash)
				if errGetAndStoreRemoteData != nil {
					return nil, "", fmt.Errorf("failure while getting and storing data from the remote "+
						"WebCAS endpoints: %w", errGetAndStoreRemoteData)
				}

				return dataFromRemote, localHL, nil
			}

			if h.ipfsReader != nil && len(ipfsLinks) > 0 {
				return h.getAndStoreDataFromIPFS(ipfsLinks[0][len(ipfsPrefix):], resourceHash)
			}

			if domain != "" {
				return h.getAndStoreDataFromDomain(domain, resourceHash)
			}
		}

		return nil, "", fmt.Errorf("failed to get data stored at %s from the local CAS: %w", resourceHash, err)
	}

	return dataFromLocal, "", nil
}

func (h *Resolver) getResourceHashWithPossibleDomainAndLinks(hashWithPossibleHint string) (string, string, []string, error) { //nolint:lll
	var domain string

	var links []string

	resourceHash := hashWithPossibleHint

	hashWithPossibleHintParts := strings.Split(hashWithPossibleHint, ":")
	if len(hashWithPossibleHintParts) == 1 {
		return resourceHash, "", nil, nil
	}

	switch hashWithPossibleHintParts[0] {
	case "https", "http":
		resourceHash = hashWithPossibleHintParts[len(hashWithPossibleHintParts)-1]

		domain = hashWithPossibleHintParts[1]

		// If the domain in the hint contains a port, this will ensure it's included.
		if len(hashWithPossibleHintParts) == cidWithPossibleHintNumPartsWithDomainPort {
			domain = fmt.Sprintf("%s:%s", domain, hashWithPossibleHintParts[2])
		}

	case "hl":
		resourceHash = hashWithPossibleHintParts[1]

		hlInfo, err := h.hl.ParseHashLink(hashWithPossibleHint)
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to parse hash link: %w", err)
		}

		links = hlInfo.Links

	case "ipfs":
		resourceHash = hashWithPossibleHintParts[1]

		cid, err := multihash.ToV1CID(resourceHash)
		if err != nil {
			return "", "", nil, fmt.Errorf("resource hash[%s] cannot be converted to V1 CID: %w", resourceHash, err)
		}

		links = []string{ipfsPrefix + cid}

	default:
		return "", "", nil, fmt.Errorf("hint '%s' not supported", hashWithPossibleHintParts[0])
	}

	return resourceHash, domain, links, nil
}

func separateLinks(links []string) ([]string, []string) {
	var webcasLinks []string

	var ipfsLinks []string

	for _, link := range links {
		switch {
		case strings.HasPrefix(link, httpsPrefix) || strings.HasPrefix(link, httpPrefix):
			webcasLinks = append(webcasLinks, link)
		case strings.HasPrefix(link, ipfsPrefix):
			ipfsLinks = append(ipfsLinks, link)
		default:
			logger.Debug("Ignoring metadata link during CAS resolution", log.WithLink(link))
		}
	}

	return webcasLinks, ipfsLinks
}

func (h *Resolver) getAndStoreDataFromDomain(domain, resourceHash string) ([]byte, string, error) {
	dataFromRemote, err := h.webCASResolver.Resolve(domain, resourceHash)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve domain and resource hash via WebCAS: %w", err)
	}

	localHL, errStoreLocallyAndVerifyHash := h.storeLocallyAndVerifyHash(dataFromRemote, resourceHash)
	if errStoreLocallyAndVerifyHash != nil {
		return nil, "", fmt.Errorf("failure while storing data retrieved from the remote "+
			"WebCAS endpoint locally: %w", errStoreLocallyAndVerifyHash)
	}

	logger.Debug("Successfully retrieved data for resource hash from HTTP(S) domain",
		log.WithHash(resourceHash), log.WithDomain(domain))

	return dataFromRemote, localHL, nil
}

func (h *Resolver) getAndStoreDataFromWebCASEndpoints(webCASEndpoints []string, cid string) ([]byte, string, error) {
	if len(webCASEndpoints) == 0 {
		return nil, "", fmt.Errorf("must provide at least one cas endpoint in order to retrieve data")
	}

	var isTransient bool

	var errMsgs []string

	for _, webCASEndpoint := range webCASEndpoints {
		data, localHL, err := h.getAndStoreDataFromWebCASEndpoint(webCASEndpoint, cid)
		if err != nil {
			errMsg := fmt.Sprintf("endpoint[%s]: %s", webCASEndpoint, err.Error())

			errMsgs = append(errMsgs, errMsg)
			isTransient = isTransient || orberrors.IsTransient(err)

			continue
		}

		return data, localHL, nil
	}

	err := fmt.Errorf("%s", errMsgs)

	if isTransient {
		return nil, "", orberrors.NewTransient(err)
	}

	return nil, "", err
}

func (h *Resolver) getAndStoreDataFromWebCASEndpoint(webCASEndpoint, cid string) ([]byte, string, error) {
	webCASEndpointLink, err := url.Parse(webCASEndpoint)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse webcas endpoint: %w", err)
	}

	dataFromRemote, err := h.webCASResolver.GetDataViaWebCASEndpoint(webCASEndpointLink)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get data via WebCAS endpoint: %w", err)
	}

	localHL, errStoreLocallyAndVerifyCID := h.storeLocallyAndVerifyHash(dataFromRemote, cid)
	if errStoreLocallyAndVerifyCID != nil {
		return nil, "", fmt.Errorf("failure while storing data retrieved from the remote "+
			"WebCAS endpoint locally: %w", errStoreLocallyAndVerifyCID)
	}

	return dataFromRemote, localHL, nil
}

func (h *Resolver) getAndStoreDataFromIPFS(cid, resourceHash string) ([]byte, string, error) {
	resp, err := h.ipfsReader.Read(cid)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read cid[%s] from ipfs: %w", cid, err)
	}

	localHL, err := h.storeLocallyAndVerifyHash(resp, resourceHash)
	if err != nil {
		return nil, "", fmt.Errorf("failure while storing data retrieved from the ipfs: %w",
			err)
	}

	return resp, localHL, nil
}

func (h *Resolver) storeLocallyAndVerifyHash(data []byte, resourceHash string) (string, error) {
	newHLFromLocalCAS, err := h.localCAS.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to CAS "+
			"(and calculate CID in the process of doing so): %w", err)
	}

	logger.Debug("Successfully stored data into CAS",
		log.WithHash(resourceHash), log.WithHashlink(newHLFromLocalCAS), log.WithCASData(data))

	newResourceHash, err := hashlink.GetResourceHashFromHashLink(newHLFromLocalCAS)
	if err != nil {
		return "", fmt.Errorf("failed to write data to CAS "+
			"(and get resource hash in the process of doing so): %w", err)
	}

	if newResourceHash != resourceHash {
		return "", fmt.Errorf("successfully stored data into the local CAS, but the resource hash produced by "+
			"the local CAS (%s) does not match the resource hash from the original request (%s)",
			newResourceHash, resourceHash)
	}

	return newHLFromLocalCAS, nil
}

// WebCASResolver is used to resolve data from another Orb server's CAS.
type WebCASResolver struct {
	httpClient         httpClient
	webFingerClient    *webfingerclient.Client
	webFingerURIScheme string
}

// NewWebCASResolver returns a new WebCASResolver.
func NewWebCASResolver(httpClient httpClient, webFingerClient *webfingerclient.Client,
	webFingerURIScheme string) WebCASResolver {
	return WebCASResolver{
		httpClient: httpClient, webFingerClient: webFingerClient, webFingerURIScheme: webFingerURIScheme,
	}
}

// Resolve returns the data stored at cid via the WebCAS hosted at domain.
// First, a WebFinger is done at domain in order to determine the WebCAS URL.
// Then the data is retrieved using the WebCAS URL.
func (w *WebCASResolver) Resolve(domain, cid string) ([]byte, error) {
	webCASURL, err := w.webFingerClient.GetWebCASURL(fmt.Sprintf("%s://%s", w.webFingerURIScheme, domain), cid)
	if err != nil {
		return nil, fmt.Errorf("failed to determine WebCAS URL via WebFinger: %w", err)
	}

	data, err := w.GetDataViaWebCASEndpoint(webCASURL)
	if err != nil {
		return nil, fmt.Errorf("failure while getting and storing data from the remote "+
			"WebCAS endpoint: %w", err)
	}

	logger.Debug("Successfully retrieved data for rom WebCAS", log.WithCID(cid),
		log.WithDomain(domain), log.WithRequestURL(webCASURL))

	return data, nil
}

// GetDataViaWebCASEndpoint retrieves data from the given webCASEndpoint and returns it.
func (w *WebCASResolver) GetDataViaWebCASEndpoint(webCASEndpoint *url.URL) ([]byte, error) {
	resp, err := w.httpClient.Get(context.Background(), transport.NewRequest(webCASEndpoint,
		transport.WithHeader(transport.AcceptHeader, transport.LDPlusJSONContentType)))
	if err != nil {
		return nil, orberrors.NewTransientf("failed to execute GET call on %s: %w",
			webCASEndpoint.String(), err)
	}

	defer func() {
		errClose := resp.Body.Close()
		if errClose != nil {
			log.CloseResponseBodyError(logger.Warn, err)
		}
	}()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to read response body from remote WebCAS endpoint: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("failed to retrieve data from %s. Response status code: %d. Response body: %s",
			webCASEndpoint.String(), resp.StatusCode, responseBody)

		if resp.StatusCode >= http.StatusInternalServerError {
			return nil, orberrors.NewTransient(err)
		}

		return nil, err
	}

	return responseBody, nil
}
