/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package restclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

type HttpRespone struct {
	Payload    []byte
	ErrorMsg   string
	StatusCode int
}

// SendRequest sends a regular POST request to the sidetree-mock
// - If post request has operation "create" then return sidetree document else no response
func SendRequest(url string, req []byte) (*HttpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

// SendResolveRequest send a regular GET request to the sidetree-mock and expects 'side tree document' argument as a response
func SendResolveRequest(url string) (*HttpRespone, error) {
	client := &http.Client{
		// TODO add tls config https://github.com/trustbloc/sidetree-mock/issues/131
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

func handleHttpResp(resp *http.Response) (*HttpRespone, error) {
	gotBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return &HttpRespone{ErrorMsg: string(gotBody), StatusCode: status}, nil
	}
	return &HttpRespone{Payload: gotBody, StatusCode: resp.StatusCode}, nil
}

func sendHTTPRequest(url string, request []byte) (*http.Response, error) {
	client := &http.Client{
		// TODO add tls config https://github.com/trustbloc/sidetree-mock/issues/131
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return client.Do(httpReq)
}

func SendResolveRequestWithRetry(url string, attempts uint8, retryableCode int, retryableCodes ...int) (*HttpRespone, error) {
	var err error
	var resp *HttpRespone

	logger.Infof("resolving: %s", url)

	codes := append(retryableCodes, retryableCode)

	remainingAttempts := attempts
	for {
		resp, err = SendResolveRequest(url)
		if err != nil {
			return nil, err
		}

		if !containsStatusCode(codes, resp.StatusCode) {
			break
		}

		logger.Infof("not found: %s - remaining attempts: %d", url, remainingAttempts)

		remainingAttempts--
		if remainingAttempts == 0 {
			break
		}

		time.Sleep(time.Second)
	}

	return resp, nil
}

func containsStatusCode(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}

	return false
}
