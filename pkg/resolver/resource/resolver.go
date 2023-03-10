/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

const (
	defaultCacheLifetime = 300 * time.Second // five minutes
	defaultCacheSize     = 100
)

var logger = log.New("resource-resolver")

type domainResolver interface {
	ResolveDomainForDID(did string) (string, error)
}

// Resolver is used for resolving host-meta resources.
type Resolver struct {
	httpClient     *http.Client
	ipfsReader     *ipfs.Client
	domainResolver domainResolver

	cacheLifetime    time.Duration
	cacheSize        int
	hostMetaDocCache gcache.Cache
}

// New returns a new Resolver.
// ipfsReader is optional. If not provided (is nil), then host-meta links specified with IPNS won't be resolvable.
func New(httpClient *http.Client, ipfsReader *ipfs.Client, domainResolver domainResolver, opts ...Option) *Resolver {
	resolver := &Resolver{
		httpClient:     httpClient,
		ipfsReader:     ipfsReader,
		domainResolver: domainResolver,
		cacheLifetime:  defaultCacheLifetime,
		cacheSize:      defaultCacheSize,
	}

	for _, opt := range opts {
		opt(resolver)
	}

	resolver.hostMetaDocCache = gcache.New(resolver.cacheSize).
		Expiration(resolver.cacheLifetime).
		LoaderFunc(func(key interface{}) (interface{}, error) {
			return resolver.resolveHostMetaLink(key.(string)) //nolint:forcetypeassert
		}).Build()

	return resolver
}

// ResolveHostMetaLink resolves a host-meta link for a given url and linkType. The url may have an HTTP, HTTPS, or
// IPNS scheme. If the url has an HTTP or HTTPS scheme, then the hostname for the host-meta call will be extracted
// from the url argument. Example: For url = https://orb.domain1.com/services/orb, this method will look for a
// host-meta document at the following URL: https://orb.domain1.com/.well-known/host-meta.
// If the resource has an IPNS scheme, then this method will look for a host-meta document stored under that IPNS
// address. In both cases, the first link in the host-meta document with a matching type will have its associated
// href value returned.
func (c *Resolver) ResolveHostMetaLink(urlToGetHostMetaFrom, linkType string) (string, error) {
	hostMetaDocumentObj, err := c.hostMetaDocCache.Get(urlToGetHostMetaFrom)
	if err != nil {
		return "", fmt.Errorf("failed to get key[%s] from host metadata cache: %w", urlToGetHostMetaFrom, err)
	}

	logger.Debug("Got value from metadata cache", logfields.WithKey(urlToGetHostMetaFrom),
		logfields.WithMetadata(hostMetaDocumentObj))

	hostMetaDocument, ok := hostMetaDocumentObj.(*discoveryrest.JRD)
	if !ok {
		return "", fmt.Errorf("unexpected value type[%T] for key[%s] in host metadata cache", hostMetaDocumentObj, urlToGetHostMetaFrom)
	}

	for _, link := range hostMetaDocument.Links {
		if link.Type == linkType {
			return link.Href, nil
		}
	}

	return "", fmt.Errorf("no links with type %s were found via %s", linkType, urlToGetHostMetaFrom)
}

func (c *Resolver) resolveHostMetaLink(urlToGetHostMetaFrom string) (*discoveryrest.JRD, error) {
	u, err := url.Parse(urlToGetHostMetaFrom)
	if err != nil {
		return nil, fmt.Errorf("parse URL [%s]: %w", urlToGetHostMetaFrom, err)
	}

	switch u.Scheme {
	case "did":
		return c.resolveHostMetaLinkFromDID(urlToGetHostMetaFrom)
	case "ipns":
		return c.resolveHostMetaLinkFromIPNS(urlToGetHostMetaFrom)
	case "http", "https":
		return c.getHostMetaDocumentViaHTTP(urlToGetHostMetaFrom)
	case "":
		return nil, fmt.Errorf("missing protocol scheme")
	default:
		return nil, fmt.Errorf(`unsupported protocol scheme "%s"`, u.Scheme)
	}
}

func (c *Resolver) resolveHostMetaLinkFromDID(did string) (*discoveryrest.JRD, error) {
	address, err := c.domainResolver.ResolveDomainForDID(did)
	if err != nil {
		return nil, fmt.Errorf("parse DID [%s]: %w", did, err)
	}

	hostMetaDocument, err := c.getHostMetaDocumentViaHTTP(address)
	if err != nil {
		return nil, fmt.Errorf("failed to get host-meta document for DID [%s] from [%s]: %w",
			did, address, err)
	}

	return hostMetaDocument, nil
}

func (c *Resolver) resolveHostMetaLinkFromIPNS(u string) (*discoveryrest.JRD, error) {
	if c.ipfsReader == nil {
		return nil, errors.New("unable to resolve since IPFS is not enabled")
	}

	hostMetaDocument, err := c.getHostMetaDocumentViaIPNS(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get host-meta document from [%s]: %w",
			u, err)
	}

	return hostMetaDocument, nil
}

func (c *Resolver) getHostMetaDocumentViaIPNS(ipnsURL string) (*discoveryrest.JRD, error) {
	ipnsURLSplitByDoubleSlashes := strings.Split(ipnsURL, "//")

	hostMetaDocumentBytes, err := c.ipfsReader.Read(fmt.Sprintf("/ipns/%s%s",
		ipnsURLSplitByDoubleSlashes[len(ipnsURLSplitByDoubleSlashes)-1], discoveryrest.HostMetaJSONEndpoint))
	if err != nil {
		return nil, fmt.Errorf("failed to read from IPNS: %w", err)
	}

	var hostMetaDocument discoveryrest.JRD

	err = json.Unmarshal(hostMetaDocumentBytes, &hostMetaDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response into a host-meta document: %w", err)
	}

	return &hostMetaDocument, nil
}

func (c *Resolver) getHostMetaDocumentViaHTTP(urlToGetHostMetaDocumentFrom string) (*discoveryrest.JRD, error) {
	parsedURL, err := url.Parse(urlToGetHostMetaDocumentFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse given URL: %w", err)
	}

	hostMetaEndpoint := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host,
		discoveryrest.HostMetaJSONEndpoint)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, hostMetaEndpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request with context: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get a response from the host-meta endpoint: %w", err)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log.CloseResponseBodyError(logger, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil,
			fmt.Errorf("got status code %d from %s (expected 200)", resp.StatusCode, hostMetaEndpoint)
	}

	hostMetaDocumentBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	logger.Debug("Host meta document for endpoint", logfields.WithServiceEndpoint(hostMetaEndpoint),
		log.WithResponse(hostMetaDocumentBytes))

	var hostMetaDocument discoveryrest.JRD

	err = json.Unmarshal(hostMetaDocumentBytes, &hostMetaDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response into a host-meta document: %w", err)
	}

	return &hostMetaDocument, nil
}

// Option is a resolver option.
type Option func(opts *Resolver)

// WithCacheLifetime option defines the lifetime of an object in the cache.
func WithCacheLifetime(lifetime time.Duration) Option {
	return func(opts *Resolver) {
		opts.cacheLifetime = lifetime
	}
}

// WithCacheSize option defines the cache size.
func WithCacheSize(size int) Option {
	return func(opts *Resolver) {
		opts.cacheSize = size
	}
}
