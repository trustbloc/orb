/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource

import (
	"encoding/json"
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

// Resolver is used for resolving WebFinger resources.
type Resolver struct {
	httpClient *http.Client
	ipfsReader *ipfs.Client
}

// New returns a new Resolver.
func New(httpClient *http.Client, ipfsReader *ipfs.Client) *Resolver {
	return &Resolver{httpClient: httpClient, ipfsReader: ipfsReader}
}

// Resolve resolves the WebFinger resource for the given property.
func (c *Resolver) Resolve(urlToResolve, property string) (string, error) {
	var err error

	var baseURLWebFingerResponse discoveryrest.WebFingerResponse

	if strings.HasPrefix(urlToResolve, "ipns://") {
		baseURLWebFingerResponse, err = c.getBaseURLWebFingerResponseViaIPNS(urlToResolve)
		if err != nil {
			return "", fmt.Errorf("failed to get WebFinger response from IPNS URL: %w", err)
		}
	} else {
		baseURLWebFingerResponse, err = c.getBaseURLWebFingerResponseViaHTTP(urlToResolve)
		if err != nil {
			return "", fmt.Errorf("failed to get WebFinger response from HTTP/HTTPS URL: %w", err)
		}
	}

	resolvedResource, err := c.resolveResourceFromBaseURLWebFingerResponse(baseURLWebFingerResponse, property)
	if err != nil {
		return "", fmt.Errorf("failed to resolve resource from Base URL WebFinger response: %w", err)
	}

	return resolvedResource, nil
}

func (c *Resolver) getBaseURLWebFingerResponseViaIPNS(ipnsURL string) (discoveryrest.WebFingerResponse, error) {
	ipnsURLSplitByDoubleSlashes := strings.Split(ipnsURL, "//")

	webFingerResponseBytes, err := c.ipfsReader.Read(fmt.Sprintf("/ipns/%s/.well-known/webfinger",
		ipnsURLSplitByDoubleSlashes[len(ipnsURLSplitByDoubleSlashes)-1]))
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to read from IPNS: %w", err)
	}

	var webFingerResponse discoveryrest.WebFingerResponse

	err = json.Unmarshal(webFingerResponseBytes, &webFingerResponse)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to unmarshal WebFinger response: %w", err)
	}

	return webFingerResponse, nil
}

func (c *Resolver) getBaseURLWebFingerResponseViaHTTP(httpURL string) (discoveryrest.WebFingerResponse, error) {
	parsedURL, err := url.Parse(httpURL)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to parse given URL: %w", err)
	}

	urlSchemeAndHost := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	webFingerURL := fmt.Sprintf("%s/.well-known/webfinger?resource=%s",
		urlSchemeAndHost, url.PathEscape(urlSchemeAndHost))

	webFingerResponse, err := c.doWebFingerViaREST(webFingerURL)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to do WebFinger via REST: %w", err)
	}

	return webFingerResponse, nil
}

func (c *Resolver) resolveResourceFromBaseURLWebFingerResponse(baseURLWebFingerResponse discoveryrest.WebFingerResponse,
	property string) (string, error) {
	retrievedPropertyRaw, exists := baseURLWebFingerResponse.Properties[property]
	if !exists {
		return "", fmt.Errorf("property missing")
	}

	retrievedProperty, ok := retrievedPropertyRaw.(string)
	if !ok {
		return "", fmt.Errorf("failed to assert property as a string")
	}

	resource, err := c.getResourceFromPropertyWebFinger(retrievedProperty)
	if err != nil {
		return "", fmt.Errorf("failed to get resource from property WebFinger: %w", err)
	}

	return resource, nil
}

func (c *Resolver) getResourceFromPropertyWebFinger(propertyWebFingerURL string) (string, error) {
	propertyWebFingerURLParsed, err := url.Parse(propertyWebFingerURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse property WebFinger URL: %w", err)
	}

	resourceWebFingerURL := fmt.Sprintf("%s://%s/.well-known/webfinger?resource=%s", propertyWebFingerURLParsed.Scheme,
		propertyWebFingerURLParsed.Host, url.PathEscape(propertyWebFingerURL))

	webFingerResponse, err := c.doWebFingerViaREST(resourceWebFingerURL)
	if err != nil {
		return "", fmt.Errorf("failed to do WebFinger via REST: %w", err)
	}

	if len(webFingerResponse.Links) > 0 {
		return webFingerResponse.Links[0].Href, nil
	}

	return "", fmt.Errorf("webfinger response contains no links")
}

func (c *Resolver) doWebFingerViaREST(webFingerURL string) (discoveryrest.WebFingerResponse, error) {
	resp, err := c.httpClient.Get(webFingerURL)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to get WebFinger response: %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			logger.Warnf("failed to close WebFinger response body: %s", err.Error())
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return discoveryrest.WebFingerResponse{},
			fmt.Errorf("got status code %d from %s (expected 200)", resp.StatusCode, webFingerURL)
	}

	webFingerResponseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	var webFingerResponse discoveryrest.WebFingerResponse

	err = json.Unmarshal(webFingerResponseBytes, &webFingerResponse)
	if err != nil {
		return discoveryrest.WebFingerResponse{}, fmt.Errorf("failed to unmarshal WebFinger response: %w", err)
	}

	return webFingerResponse, nil
}
