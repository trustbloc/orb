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
)

const (
	authHeader  = "Authorization"
	tokenPrefix = "Bearer "
)

type httpClient struct {
	state *state
}

func newHTTPClient(state *state) *httpClient {
	return &httpClient{state: state}
}

func (c *httpClient) Get(url string) ([]byte, int, http.Header, error) {
	client := &http.Client{}
	defer client.CloseIdleConnections()

	if strings.HasPrefix(url, "https") {
		// TODO add tls config https://github.com/trustbloc/fabric-peer-test-common/issues/51
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}
	}

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, nil, err
	}

	c.setAuthTokenHeader(httpReq)

	resp, err := client.Do(httpReq)
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
	client := &http.Client{}
	defer client.CloseIdleConnections()

	if strings.HasPrefix(url, "https") {
		// TODO add tls config https://github.com/trustbloc/fabric-peer-test-common/issues/51
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}
	}

	logger.Infof("Posting request of content-type [%s] to [%s]: %s", contentType, url, data)

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, nil, err
	}

	httpReq.Header.Set("Content-Type", contentType)

	c.setAuthTokenHeader(httpReq)

	resp, err := client.Do(httpReq)
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
