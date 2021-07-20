/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/ipfs"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

var logger = log.New("resource-resolver")

// Resolver is used for resolving host-meta resources.
type Resolver struct {
	httpClient *http.Client
	ipfsReader *ipfs.Client
}

// New returns a new Resolver.
// ipfsReader is optional. If not provided (is nil), then host-meta links specified with IPNS won't be resolvable.
func New(httpClient *http.Client, ipfsReader *ipfs.Client) *Resolver {
	return &Resolver{httpClient: httpClient, ipfsReader: ipfsReader}
}

// ResolveHostMetaLink resolves a host-meta link for a given url and linkType. The url may have an HTTP, HTTPS, or
// IPNS scheme. If the url has an HTTP or HTTPS scheme, then the hostname for the host-meta call will be extracted
// from the url argument. Example: For url = https://orb.domain1.com/services/orb, this method will look for a
// host-meta document at the following URL: https://orb.domain1.com/.well-known/host-meta.
// If the resource has an IPNS scheme, then this method will look for a host-meta document stored under that IPNS
// address. In both cases, the first link in the host-meta document with a matching type will have its associated
// href value returned.
func (c *Resolver) ResolveHostMetaLink(urlToGetHostMetaFrom, linkType string) (string, error) {
	var err error

	var hostMetaDocument discoveryrest.JRD

	if strings.HasPrefix(urlToGetHostMetaFrom, "ipns://") {
		if c.ipfsReader == nil {
			return "", errors.New("unable to resolve since IPFS is not enabled")
		}

		hostMetaDocument, err = c.getHostMetaDocumentViaIPNS(urlToGetHostMetaFrom)
		if err != nil {
			return "", fmt.Errorf("failed to get host-meta document via IPNS: %w", err)
		}
	} else {
		hostMetaDocument, err = c.getHostMetaDocumentViaHTTP(urlToGetHostMetaFrom)
		if err != nil {
			return "", fmt.Errorf("failed to get host-meta document via HTTP/HTTPS: %w", err)
		}
	}

	for _, link := range hostMetaDocument.Links {
		if link.Type == linkType {
			return link.Href, nil
		}
	}

	return "", fmt.Errorf("no links with type %s were found via %s", linkType, urlToGetHostMetaFrom)
}

func (c *Resolver) getHostMetaDocumentViaIPNS(ipnsURL string) (discoveryrest.JRD, error) {
	ipnsURLSplitByDoubleSlashes := strings.Split(ipnsURL, "//")

	hostMetaDocumentBytes, err := c.ipfsReader.Read(fmt.Sprintf("/ipns/%s%s",
		ipnsURLSplitByDoubleSlashes[len(ipnsURLSplitByDoubleSlashes)-1], discoveryrest.HostMetaJSONEndpoint))
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to read from IPNS: %w", err)
	}

	var hostMetaDocument discoveryrest.JRD

	err = json.Unmarshal(hostMetaDocumentBytes, &hostMetaDocument)
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to unmarshal response into a host-meta document: %w", err)
	}

	return hostMetaDocument, nil
}

func (c *Resolver) getHostMetaDocumentViaHTTP(urlToGetHostMetaDocumentFrom string) (discoveryrest.JRD, error) {
	parsedURL, err := url.Parse(urlToGetHostMetaDocumentFrom)
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to parse given URL: %w", err)
	}

	hostNameWithScheme := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	hostMetaEndpoint := fmt.Sprintf("%s%s", hostNameWithScheme, discoveryrest.HostMetaJSONEndpoint)

	hostMetaDocument, err := c.getHostMetaDocumentFromEndpoint(hostMetaEndpoint)
	if err != nil {
		return discoveryrest.JRD{}, err
	}

	return hostMetaDocument, nil
}

func (c *Resolver) getHostMetaDocumentFromEndpoint(hostMetaEndpoint string) (discoveryrest.JRD, error) {
	resp, err := c.httpClient.Get(hostMetaEndpoint)
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to get a response from the host-meta endpoint: %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close host-meta response body: %s", err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return discoveryrest.JRD{},
			fmt.Errorf("got status code %d from %s (expected 200)", resp.StatusCode, hostMetaEndpoint)
	}

	hostMetaDocumentBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var hostMetaDocument discoveryrest.JRD

	logger.Debugf("Host meta document for endpoint [%s]: %s", hostMetaEndpoint, hostMetaDocumentBytes)

	err = json.Unmarshal(hostMetaDocumentBytes, &hostMetaDocument)
	if err != nil {
		return discoveryrest.JRD{}, fmt.Errorf("failed to unmarshal response into a host-meta document: %w", err)
	}

	return hostMetaDocument, nil
}
