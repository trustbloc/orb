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

type httpClient struct {
	context *BDDContext
	state   *state
	client  *http.Client
	signers map[string]signFunc
	mutex   sync.RWMutex
}

func newHTTPClient(state *state, context *BDDContext) *httpClient {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		},
	}

	return &httpClient{
		state:  state,
		client: client,
	}
}

func (c *httpClient) Get(url string) ([]byte, int, http.Header, error) {
	return c.GetWithSignature(url, "")
}

func (c *httpClient) GetWithSignature(url, domain string) ([]byte, int, http.Header, error) {
	defer c.client.CloseIdleConnections()

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, nil, err
	}

	c.setAuthTokenHeader(httpReq)

	if domain != "" {
		sign, err := c.signer(domain)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("get with signature: %w", err)
		}

		err = sign(httpReq)
		if err != nil {
			return nil, 0, nil, err
		}
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, 0, nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, resp.Header, fmt.Errorf("reading response body failed: %s", err)
	}

	return payload, resp.StatusCode, resp.Header, nil
}

func (c *httpClient) Post(url string, data []byte, contentType string) ([]byte, int, http.Header, error) {
	return c.PostWithSignature(url, data, contentType, "")
}

func (c *httpClient) PostWithSignature(url string, data []byte, contentType, domain string) ([]byte, int, http.Header, error) {
	defer c.client.CloseIdleConnections()

	logger.Infof("Posting request of content-type [%s] to [%s]: %s", contentType, url, data)

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, nil, err
	}

	httpReq.Header.Set("Content-Type", contentType)

	c.setAuthTokenHeader(httpReq)

	if domain != "" {
		sign, err := c.signer(domain)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("post with signature: %w", err)
		}

		err = sign(httpReq)
		if err != nil {
			return nil, 0, nil, err
		}
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, 0, nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}

	return payload, resp.StatusCode, resp.Header, nil
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
		logger.Infof("Could not find bearer token for path [%s]", req.URL.Path)
		return
	}

	logger.Infof("Setting authorization header for bearer token [%s] for path [%s]", authToken, req.URL.Path)

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

func printResponse(statusCode int, payload []byte, header http.Header) {
	respContentType, ok := header["Content-Type"]
	if ok {
		switch {
		case strings.HasPrefix(respContentType[0], "image/"):
			logger.Infof("Received status code %d and an image of type [%s]", statusCode, respContentType[0])
		case strings.HasPrefix(respContentType[0], "text/"):
			logger.Infof("Received status code %d and a text response: %s", statusCode, payload)
		default:
			logger.Infof("Received status code %d and a response of type [%s]:\n%s", statusCode, respContentType[0], payload)
		}
	} else {
		logger.Infof("Received status code %d and a response with no Content-Type:\n%s", statusCode, payload)
	}
}

func date() string {
	return fmt.Sprintf("%s GMT", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05"))
}
