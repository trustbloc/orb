/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	authHeader  = "Authorization"
	tokenPrefix = "Bearer "
)

type signerConfig struct {
	kmsStoreURL string
	kmsKeyID    string
	publicKeyID string
}

type signFunc = func(req *http.Request) error

type httpResponse struct {
	Payload    []byte
	ErrorMsg   string
	StatusCode int
	Header     http.Header
}

type httpClient struct {
	context  *BDDContext
	state    *state
	client   *http.Client
	signers  map[string]signFunc
	mutex    sync.RWMutex
	mappings map[string]string
}

func newHTTPClient(state *state, context *BDDContext) *httpClient {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		},
	}

	return &httpClient{
		state:    state,
		client:   client,
		mappings: make(map[string]string),
	}
}

func (c *httpClient) Get(url string) (*httpResponse, error) {
	return c.GetWithSignature(url, "")
}

func (c *httpClient) GetWithSignature(url, domain string) (*httpResponse, error) {
	defer c.client.CloseIdleConnections()

	url = c.resolveURL(url)

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	c.setAuthTokenHeader(httpReq)

	if domain != "" {
		sign, err := c.signer(domain)
		if err != nil {
			return nil, fmt.Errorf("get with signature: %w", err)
		}

		err = sign(httpReq)
		if err != nil {
			return nil, err
		}
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &httpResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			ErrorMsg:   string(payload),
		}, nil
	}

	return &httpResponse{
		Payload:    payload,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}, nil
}

func (c *httpClient) GetWithRetry(url string, attempts uint8, retryableCode int, retryableCodes ...int) (*httpResponse, error) {
	var err error
	var resp *httpResponse

	logger.Infof("resolving: %s", url)

	codes := append(retryableCodes, retryableCode)

	remainingAttempts := attempts
	for {
		resp, err = c.Get(url)
		if err != nil {
			return nil, err
		}

		if !containsStatusCode(codes, resp.StatusCode) {
			break
		}

		logger.Infof("Status code %d: %s - %s - remaining attempts: %d",
			resp.StatusCode, resp.ErrorMsg, url, remainingAttempts)

		remainingAttempts--
		if remainingAttempts == 0 {
			break
		}

		time.Sleep(2 * time.Second)
	}

	return resp, nil
}

func (c *httpClient) Post(url string, data []byte, contentType string) (*httpResponse, error) {
	return c.PostWithSignature(url, data, contentType, "")
}

func (c *httpClient) PostWithSignature(url string, data []byte, contentType, domain string) (*httpResponse, error) {
	defer c.client.CloseIdleConnections()

	url = c.resolveURL(url)

	logger.Infof("Posting request of content-type [%s] to [%s]: %s", contentType, url, data)

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", contentType)

	c.setAuthTokenHeader(httpReq)

	if domain != "" {
		sign, err := c.signer(domain)
		if err != nil {
			return nil, fmt.Errorf("post with signature: %w", err)
		}

		err = sign(httpReq)
		if err != nil {
			return nil, err
		}
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return &httpResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			ErrorMsg:   string(payload),
		}, nil
	}

	return &httpResponse{
		Payload:    payload,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}, nil
}

// setAuthTokenHeader sets the bearer token in the Authorization header if one
// is defined for the given request path.
func (c *httpClient) setAuthTokenHeader(req *http.Request) {
	logger.Debugf("Looking for authorization token for URL [%s]", req.URL.Path)

	authToken := ""
	parts := strings.Split(req.URL.Path, "/")

	for i := len(parts); i > 1; i-- {
		basePath := strings.Join(parts[0:i], "/")
		logger.Debugf("... resolving authorization token for path [%s]", basePath)

		authToken = c.state.getAuthToken(basePath, req.Method)
		if authToken != "" {
			break
		}
	}

	if authToken == "" {
		logger.Debugf("Could not find bearer token for path [%s]", req.URL.Path)
		return
	}

	logger.Debugf("Setting authorization header for bearer token [%s] for path [%s]", authToken, req.URL.Path)

	req.Header.Set(authHeader, tokenPrefix+authToken)
}

func (c *httpClient) signer(domain string) (signFunc, error) {
	c.mutex.RLock()
	signers := c.signers
	c.mutex.RUnlock()

	if signers != nil {
		signer, ok := signers[domain]
		if !ok {
			return nil, fmt.Errorf("signer not found for domain [%s]", domain)
		}

		return signer, nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.signers = make(map[string]signFunc)

	for domain, pubKeyID := range domains {
		cfg, err := getSignerConfig(domain, pubKeyID)
		if err != nil {
			return nil, fmt.Errorf("new store provider: %w", err)
		}

		pubKeyID := cfg.publicKeyID

		s := newKMSSigner(cfg.kmsStoreURL, cfg.kmsKeyID, c.client)

		c.signers[domain] = func(req *http.Request) error {
			return s.sign(pubKeyID, req)
		}
	}

	signer, ok := c.signers[domain]
	if !ok {
		return nil, fmt.Errorf("signer not found for domain [%s]", domain)
	}

	return signer, nil
}

func (c *httpClient) MapDomain(domain string, mapping string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	logger.Infof("Mapping domain %s to %s", domain, mapping)

	c.mappings[domain] = mapping
}

func (c *httpClient) resolveURL(url string) string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for domain, mapping := range c.mappings {
		if strings.Contains(url, "//"+domain) {
			logger.Infof("Mapping %s to %s", domain, mapping)

			return strings.Replace(url, "//"+domain, "//"+mapping, 1)
		}
	}

	return url
}

func contentTypeFromFileName(fileName string) (string, error) {
	p := strings.LastIndex(fileName, ".")
	if p == -1 {
		return "", fmt.Errorf("content type cannot be deduced since no file extension provided")
	}

	contentType := mime.TypeByExtension(fileName[p:])
	if contentType == "" {
		return "", fmt.Errorf("content type cannot be deduced from extension")
	}

	return contentType, nil
}

func printResponse(resp *httpResponse) {
	respContentType, ok := resp.Header["Content-Type"]
	if ok {
		switch {
		case strings.HasPrefix(respContentType[0], "image/"):
			logger.Infof("Received status code %d and an image of type [%s]", resp.StatusCode, respContentType[0])
		case strings.HasPrefix(respContentType[0], "text/"):
			logger.Infof("Received status code %d and a text response: %s", resp.StatusCode, resp.Payload)
		default:
			logger.Infof("Received status code %d and a response of type [%s]:\n%s", resp.StatusCode, respContentType[0], resp.Payload)
		}
	} else {
		logger.Infof("Received status code %d and a response with no Content-Type:\n%s", resp.StatusCode, resp.Payload)
	}
}

func date() string {
	return fmt.Sprintf("%s GMT", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05"))
}

func containsStatusCode(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}

	return false
}
