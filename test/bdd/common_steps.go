/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/tidwall/gjson"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

const (
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMongoDBOption = "mongodb"

	configStoreID = "orb-config"

	webKeyStoreKey = "web-key-store"
	kidKey         = "kid"

	databaseTypeEnvVar = "DATABASE_TYPE"
	databaseURLEnvVar  = "DATABASE_URL"
	kmsEndpointEnvVar  = "ORB_KMS_ENDPOINT"
)

var domains = map[string]string{
	"domain1": "https://orb.domain1.com/services/orb/keys/main-key",
	"domain2": "https://orb.domain2.com/services/orb/keys/main-key",
	"domain3": "https://orb.domain3.com/services/orb/keys/main-key",
}

// CommonSteps contain BDDContext
type CommonSteps struct {
	BDDContext           *BDDContext
	state                *state
	httpClient           *httpClient
	ipnsDocumentUploaded bool
}

// NewCommonSteps create new CommonSteps struct
func NewCommonSteps(context *BDDContext, state *state) *CommonSteps {
	return &CommonSteps{
		BDDContext: context,
		state:      state,
		httpClient: newHTTPClient(state, context),
	}
}

func (d *CommonSteps) wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds", seconds)

	time.Sleep(time.Duration(seconds) * time.Second)

	return nil
}

func (d *CommonSteps) setVariableFromResponse(key string) error {
	logger.Infof("Saving value %s to variable %s", d.state.getResponse(), key)

	d.state.setVar(key, d.state.getResponse())

	return nil
}

func (d *CommonSteps) setVariable(varName, value string) error {
	if err := d.state.resolveVarsInExpression(&value); err != nil {
		return err
	}

	logger.Infof("Setting var [%s] to [%s]", varName, value)

	d.state.setVar(varName, value)

	return nil
}

func (d *CommonSteps) setJSONVariable(varName, value string) error {
	m := make(map[string]interface{})
	var bytes []byte

	// First resolve all of the raw JSON variables.
	value, err := d.state.resolveWithPrefix("#", value)
	if err != nil {
		return fmt.Errorf("invalid JSON %s: %w", value, err)
	}

	if err := json.Unmarshal([]byte(value), &m); err != nil {
		var arr []interface{}
		if err := json.Unmarshal([]byte(value), &arr); err != nil {
			return fmt.Errorf("invalid JSON %s: %w", value, err)
		}

		arr, err = d.state.resolveArray(arr)
		if err != nil {
			return err
		}

		bytes, err = json.Marshal(arr)
		if err != nil {
			return err
		}
	} else {
		doc, err := d.state.resolveMap(m)
		if err != nil {
			return err
		}

		bytes, err = json.Marshal(doc)
		if err != nil {
			return err
		}
	}

	d.state.setVar(varName, string(bytes))

	return nil
}

func (d *CommonSteps) setUUIDVariable(varName string) error {
	value := uuid.New().String()

	logger.Infof("Setting var [%s] to [%s]", varName, value)

	d.state.setVar(varName, value)

	return nil
}

func (d *CommonSteps) jsonPathOfResponseEquals(path, expected string) error {
	resolved, err := d.state.resolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Str)
	if r.Str == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Str, expected)
}

func (d *CommonSteps) jsonPathOfNumericResponseEquals(path, expected string) error {
	resolved, err := d.state.resolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %g", path, d.state.getResponse(), r.Num)

	strNum := strconv.FormatFloat(r.Num, 'f', -1, 64)
	if strNum == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%g] which is not the expected value [%s]", r.Num, expected)
}

func (d *CommonSteps) jsonPathOfBoolResponseEquals(path, expected string) error {
	resolved, err := d.state.resolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %t", path, d.state.getResponse(), r.Bool())

	strBool := strconv.FormatBool(r.Bool())
	if strBool == expected {
		return nil
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", strBool, expected)
}

func (d *CommonSteps) jsonPathOfResponseHasNumItems(path string, expectedNum int) error {
	r := gjson.Get(d.state.getResponse(), path)
	logger.Infof("Path [%s] of JSON %s resolves to %d items", path, d.state.getResponse(), int(r.Num))
	if int(r.Num) == expectedNum {
		return nil
	}
	return fmt.Errorf("JSON path resolves to [%d] items which is not the expected number of items [%d]", int(r.Num), expectedNum)
}

func (d *CommonSteps) jsonPathOfResponseContains(path, expected string) error {
	resolved, err := d.state.resolveVars(expected)
	if err != nil {
		return err
	}

	expected = resolved.(string)

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Raw)

	for _, a := range r.Array() {
		if a.Str == expected {
			return nil
		}
	}

	return fmt.Errorf("JSON path resolves to [%s] which is not the expected value [%s]", r.Array(), expected)
}

func (d *CommonSteps) jsonPathOfResponseContainsRegEx(path, pattern string) error {
	resolvedRegEx, err := d.state.resolveVars(pattern)
	if err != nil {
		return err
	}

	regEx, err := regexp.Compile(resolvedRegEx.(string))
	if err != nil {
		return err
	}

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Raw)

	for _, a := range r.Array() {
		if regEx.MatchString(a.Str) {
			return nil
		}
	}

	return fmt.Errorf("JSON path resolves to [%s] which does not match the regular expression [%s]",
		r.Array(), pattern)
}

func (d *CommonSteps) jsonPathOfResponseNotContains(path, notExpected string) error {
	resolved, err := d.state.resolveVars(notExpected)
	if err != nil {
		return err
	}

	notExpected = resolved.(string)

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Raw)

	for _, a := range r.Array() {
		if a.Str == notExpected {
			return fmt.Errorf("JSON path resolves to [%s] which contains value [%s]", r.Array(), notExpected)
		}
	}

	return nil
}

func (d *CommonSteps) jsonPathOfResponseNotContainsRegEx(path, pattern string) error {
	resolvedRegEx, err := d.state.resolveVars(pattern)
	if err != nil {
		return err
	}

	regEx, err := regexp.Compile(resolvedRegEx.(string))
	if err != nil {
		return err
	}

	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Raw)

	for _, a := range r.Array() {
		if regEx.MatchString(a.Str) {
			return fmt.Errorf("JSON path resolves to [%s] which contains pattern [%s]", r.Array(), pattern)
		}
	}

	return nil
}

func (d *CommonSteps) jsonPathOfResponseSavedToVar(path, varName string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s. Saving to variable [%s]", path, d.state.getResponse(), r.Str, varName)

	d.state.setVar(varName, r.Str)

	return nil
}

func (d *CommonSteps) jsonPathOfNumericResponseSavedToVar(path, varName string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %g. Saving to variable [%s]", path, d.state.getResponse(), r.Num, varName)

	d.state.setVar(varName, strconv.FormatFloat(r.Num, 'f', -1, 64))

	return nil
}

func (d *CommonSteps) jsonPathOfRawResponseSavedToVar(path, varName string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s. Saving to variable [%s]", path, d.state.getResponse(), r.Raw, varName)

	d.state.setVar(varName, r.Raw)

	return nil
}

func (d *CommonSteps) jsonPathOfBoolResponseSavedToVar(path, varName string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %t. Saving to variable [%s]", path, d.state.getResponse(), r.Bool(), varName)

	d.state.setVar(varName, strconv.FormatBool(r.Bool()))

	return nil
}

func (d *CommonSteps) jsonPathOfResponseNotEmpty(path string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Str)
	if len(r.Str) > 0 {
		return nil
	}

	return fmt.Errorf("JSON path resolves to an empty value")
}

func (d *CommonSteps) jsonPathOfArrayResponseNotEmpty(path string) error {
	r := gjson.Get(d.state.getResponse(), path)

	logger.Infof("Path [%s] of JSON %s resolves to %s", path, d.state.getResponse(), r.Array())

	if len(r.Array()) > 0 {
		logger.Infof("Path [%s] of JSON %s resolves to %d array elements", path, d.state.getResponse(), len(r.Array()))

		return nil
	}

	return fmt.Errorf("JSON path [%s] resolves to an empty array", path)
}

func (d *CommonSteps) valueOfJSONStringResponseSavedToVar(varName string) error {
	var value string

	if err := json.Unmarshal([]byte(d.state.getResponse()), &value); err != nil {
		return fmt.Errorf("invalid JSON string in response [%s]", d.state.getResponse())
	}

	logger.Infof("Saving [%s] to variable [%s]", value, varName)

	d.state.setVar(varName, value)

	return nil
}

func (d *CommonSteps) responseEquals(value string) error {
	if d.state.getResponse() == value {
		logger.Infof("Response equals expected value [%s]", value)
		return nil
	}

	return fmt.Errorf("Response [%s] does not equal expected value [%s]", d.state.getResponse(), value)
}

func (d *CommonSteps) httpGetWithExpectedCode(url string, expectingCode int) error {
	resp, err := d.doHTTPGet(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	return nil
}

func (d *CommonSteps) httpGet(url string) error {
	d.state.clearResponse()

	resp, err := d.doHTTPGet(url)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) httpGetWithSignature(url, pubKeyID string) error {
	d.state.clearResponse()

	resp, err := d.doHTTPGetWithSignature(url, pubKeyID)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) httpGetWithSignatureAndExpectedCode(url, pubKeyID string, expectingCode int) error {
	resp, err := d.doHTTPGetWithSignature(url, pubKeyID)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	return nil
}

func (d *CommonSteps) httpPostFile(url, path string) error {
	resp, err := d.doHTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	return nil
}

func (d *CommonSteps) httpPostFileWithExpectedCode(url, path string, expectingCode int) error {
	resp, err := d.doHTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	return nil
}

func (d *CommonSteps) httpPostFileWithSignature(url, path, pubKeyID string) error {
	resp, err := d.doHTTPPostFileWithSignature(url, path, pubKeyID)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	return nil
}

func (d *CommonSteps) httpPostFileWithSignatureAndExpectedCode(url, path, pubKeyID string, expectingCode int) error {
	resp, err := d.doHTTPPostFileWithSignature(url, path, pubKeyID)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	return nil
}

func (d *CommonSteps) httpPost(url, data, contentType string) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	resp, err := d.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) httpPostWithSignature(url, data, contentType, domain string) error {
	d.state.clearResponse()

	err := d.state.resolveVarsInExpression(&data, &domain)
	if err != nil {
		return err
	}

	resp, err := d.doHTTPPostWithSignature(url, []byte(data), contentType, domain)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) httpPostWithExpectedCode(url, data, contentType string, expectingCode int) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	resp, err := d.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) httpPostWithSignatureAndExpectedCode(url, data, contentType, domain string, expectingCode int) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	resp, err := d.doHTTPPostWithSignature(url, []byte(data), contentType, domain)
	if err != nil {
		return err
	}

	if resp.StatusCode != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, resp.StatusCode)
	}

	logger.Infof("Returned status code is %d which is the expected status code", resp.StatusCode)

	d.state.setResponse(string(resp.Payload))

	return nil
}

func (d *CommonSteps) doHTTPGet(url string) (*httpResponse, error) {
	resolved, err := d.state.resolveVars(url)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.GetWithRetry(resolved.(string), 10, http.StatusBadGateway)
	if err != nil {
		return nil, err
	}

	printResponse(resp)

	return resp, nil
}

func (d *CommonSteps) doHTTPGetWithSignature(url, domain string) (*httpResponse, error) {
	err := d.state.resolveVarsInExpression(&url, &domain)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.GetWithSignature(url, domain)
	if err != nil {
		return nil, err
	}

	printResponse(resp)

	return resp, nil
}

func (d *CommonSteps) doHTTPPost(url string, content []byte, contentType string) (*httpResponse, error) {
	resolved, err := d.state.resolveVars(url)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.Post(resolved.(string), content, contentType)
	if err != nil {
		return nil, err
	}

	printResponse(resp)

	return resp, nil
}

func (d *CommonSteps) doHTTPPostWithSignature(url string, content []byte, contentType, domain string) (*httpResponse, error) {
	err := d.state.resolveVarsInExpression(&url, &domain)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.PostWithSignature(url, content, contentType, domain)
	if err != nil {
		return nil, err
	}

	printResponse(resp)

	return resp, nil
}

func (d *CommonSteps) doHTTPPostFile(url, path string) (*httpResponse, error) {
	return d.doHTTPPostFileWithSignature(url, path, "")
}

func (d *CommonSteps) doHTTPPostFileWithSignature(url, path, domain string) (*httpResponse, error) {
	d.state.clearResponse()

	logger.Infof("Uploading file [%s] to [%s]", path, url)

	contentType, err := contentTypeFromFileName(path)
	if err != nil {
		return nil, err
	}

	contents, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	resp, err := d.doHTTPPostWithSignature(url, contents, contentType, domain)
	if err != nil {
		return nil, err
	}

	d.state.setResponse(string(resp.Payload))

	return resp, nil
}

func (d *CommonSteps) valuesEqual(value1, value2 string) error {
	if err := d.state.resolveVarsInExpression(&value1, &value2); err != nil {
		return err
	}

	if value1 == value2 {
		logger.Infof("Values are equal [%s]=[%s]", value1, value2)

		return nil
	}

	logger.Infof("Value1 [%s] does not equal value 2 [%s]", value1, value2)

	return fmt.Errorf("values [%s] and [%s] are not equal", value1, value2)
}

func (d *CommonSteps) valuesNotEqual(value1, value2 string) error {
	if err := d.state.resolveVarsInExpression(&value1, &value2); err != nil {
		return err
	}

	if value1 != value2 {
		logger.Infof("Values are not equal [%s]!=[%s]", value1, value2)

		return nil
	}

	logger.Infof("Value1 [%s] equals value 2 [%s]", value1, value2)

	return fmt.Errorf("values [%s] and [%s] are equal", value1, value2)
}

func (d *CommonSteps) setAuthTokenForPath(method, path, token string) error {
	if err := d.state.resolveVarsInExpression(&method, &path, &token); err != nil {
		return err
	}

	logger.Debugf("Setting authorization bearer token for [%s] (%s) to [%s]", path, method, token)

	d.state.setAuthToken(path, method, token)

	return nil
}

func (d *CommonSteps) mapHTTPDomain(domain, mapping string) error {
	d.httpClient.MapDomain(domain, mapping)

	return nil
}

func (d *CommonSteps) hostMetaDocumentIsUploadedToIPNS() error {
	ipfs := shell.NewShell("http://localhost:5001")

	ipfs.SetTimeout(20 * time.Second)

	_, err := ipfs.Cat(fmt.Sprintf("/ipns/k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q%s",
		discoveryrest.HostMetaJSONEndpoint))
	if err == nil {
		logger.Infof("IPNS document already uploaded. Skipping upload step.")

		pathToPin := fmt.Sprintf("/ipns/k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q%s",
			discoveryrest.HostMetaJSONEndpoint)

		logger.Infof("Pinning %s to the local node.", pathToPin)

		err = ipfs.Pin(fmt.Sprintf("/ipns/k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q%s",
			discoveryrest.HostMetaJSONEndpoint))
		if err != nil {
			return err
		}

		logger.Infof("Successfully pinned %s to the local node.", pathToPin)

		return nil
	}

	logger.Infof("Generating key for IPNS...")

	_, err = execCMD("ipfs", "key-gen", "--ipfs-url=http://localhost:5001",
		"--key-name=OrbBDDTestKey",
		"--privatekey-ed25519=9kRTh70Ut0MKPeHY3Gdv/pi8SACx6dFjaEiIHf7JDugPpXBnCHVvRbgdzYbWfCGsXdvh/Zct+AldKG4bExjHXg")
	if err == nil {
		logger.Infof("Done generating key for IPNS.")
	} else {
		if !strings.Contains(err.Error(), "key with name 'OrbBDDTestKey' already exists") {
			return fmt.Errorf("failed to execute command: %w", err)
		}
		logger.Infof("Key already generated.")
	}

	logger.Infof("Generating host-meta file...")

	attemptsCount := 0

	err = backoff.Retry(func() error {
		attemptsCount++

		_, err = execCMD("ipfs", "host-meta-doc-gen", "--ipfs-url=http://localhost:5001",
			"--resource-url=https://localhost:48326",
			"--key-name=OrbBDDTestKey", "--tls-cacerts=fixtures/keys/tls/ec-cacert.pem")
		if err != nil {
			logger.Infof("Failed to generate host-meta document (attempt %d): %s", attemptsCount, err)
			return err
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*3), 15))
	if err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}

	logger.Infof("Done generating host-meta file.")

	logger.Infof("Uploading host-meta file to IPNS... this may take several minutes...")

	value, err := execCMD("ipfs", "host-meta-dir-upload", "--ipfs-url=http://localhost:5001",
		"--key-name=OrbBDDTestKey", "--host-meta-input-dir=./website")
	if err != nil {
		return fmt.Errorf("failed to execute command: %s", err)
	}

	logger.Infof("Done uploading host-meta file. Command output: %s", value)

	return nil
}

func getSignerConfig(domain, pubKeyID string) (*signerConfig, error) {
	storeProvider, err := newStoreProvider(domain)
	if err != nil {
		return nil, fmt.Errorf("new store provider: %w", err)
	}

	cfgStore, err := storeProvider.OpenStore(configStoreID)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	keyID, err := getConfig(cfgStore, kidKey)
	if err != nil {
		return nil, fmt.Errorf("get config value for %q: %w", kidKey, err)
	}

	kmsURL, err := getConfig(cfgStore, webKeyStoreKey)
	if err != nil {
		return nil, fmt.Errorf("get config value for %q: %w", webKeyStoreKey, err)
	}

	u, err := url.Parse(kmsURL)
	if err != nil {
		return nil, fmt.Errorf("parse KMS URL: %w", err)
	}

	kmsEndpoint := os.Getenv(kmsEndpointEnvVar)
	if kmsEndpoint == "" {
		return nil, fmt.Errorf("env var not set: %s", kmsEndpointEnvVar)
	}

	kmsURL = fmt.Sprintf("%s%s", kmsEndpoint, u.Path)

	logger.Infof("[%s] Using KMS URL: %s", domain, kmsURL)

	return &signerConfig{
		kmsStoreURL: kmsURL,
		kmsKeyID:    keyID,
		publicKeyID: pubKeyID,
	}, nil
}

func getConfig(store storage.Store, key string) (string, error) {
	src, err := store.Get(key)
	if err != nil {
		return "", fmt.Errorf("get config value for %q: %w", kidKey, err)
	}

	var value string

	err = json.Unmarshal(src, &value)
	if err != nil {
		return "", fmt.Errorf("unmarshal KMS URL: %w", err)
	}

	return value, nil
}

func newStoreProvider(domain string) (storage.Provider, error) {
	databaseType := os.Getenv(databaseTypeEnvVar)
	databaseURL := os.Getenv(databaseURLEnvVar)

	if databaseType == "" {
		return nil, fmt.Errorf("env var not set: %s", databaseTypeEnvVar)
	}

	if databaseURL == "" {
		return nil, fmt.Errorf("env var not set: %s", databaseURLEnvVar)
	}

	switch databaseType {
	case databaseTypeCouchDBOption:
		return ariescouchdbstorage.NewProvider(databaseURL, ariescouchdbstorage.WithDBPrefix(domain))

	case databaseTypeMongoDBOption:
		return ariesmongodbstorage.NewProvider(databaseURL, ariesmongodbstorage.WithDBPrefix(domain))

	default:
		return nil, fmt.Errorf("unsupported database type [%s]", databaseType)
	}
}

// RegisterSteps register steps
func (d *CommonSteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(d.BDDContext.BeforeScenario)
	s.AfterScenario(d.BDDContext.AfterScenario)

	s.Step(`^we wait (\d+) seconds$`, d.wait)
	s.Step(`^the response is saved to variable "([^"]*)"$`, d.setVariableFromResponse)
	s.Step(`^the response equals "([^"]*)"$`, d.responseEquals)
	s.Step(`^the value "([^"]*)" equals "([^"]*)"$`, d.valuesEqual)
	s.Step(`^the value "([^"]*)" does not equal "([^"]*)"$`, d.valuesNotEqual)
	s.Step(`^variable "([^"]*)" is assigned the value "([^"]*)"$`, d.setVariable)
	s.Step(`^variable "([^"]*)" is assigned the JSON value '([^']*)'$`, d.setJSONVariable)
	s.Step(`^variable "([^"]*)" is assigned the uncanonicalized JSON value '([^']*)'$`, d.setVariable)
	s.Step(`^the JSON path "([^"]*)" of the response equals "([^"]*)"$`, d.jsonPathOfResponseEquals)
	s.Step(`^the JSON path '([^']*)' of the response equals "([^"]*)"$`, d.jsonPathOfResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the numeric response equals "([^"]*)"$`, d.jsonPathOfNumericResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the boolean response equals "([^"]*)"$`, d.jsonPathOfBoolResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the response has (\d+) items$`, d.jsonPathOfResponseHasNumItems)
	s.Step(`^the JSON path "([^"]*)" of the response contains "([^"]*)"$`, d.jsonPathOfResponseContains)
	s.Step(`^the JSON path '([^']*)' of the response contains "([^"]*)"$`, d.jsonPathOfResponseContains)
	s.Step(`^the JSON path "([^"]*)" of the response contains expression "([^"]*)"$`, d.jsonPathOfResponseContainsRegEx)
	s.Step(`^the JSON path "([^"]*)" of the response does not contain "([^"]*)"$`, d.jsonPathOfResponseNotContains)
	s.Step(`^the JSON path "([^"]*)" of the response does not contain expression "([^"]*)"$`, d.jsonPathOfResponseNotContainsRegEx)
	s.Step(`^the JSON path "([^"]*)" of the response is saved to variable "([^"]*)"$`, d.jsonPathOfResponseSavedToVar)
	s.Step(`^the JSON path '([^']*)' of the response is saved to variable "([^"]*)"$`, d.jsonPathOfResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the numeric response is saved to variable "([^"]*)"$`, d.jsonPathOfNumericResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the boolean response is saved to variable "([^"]*)"$`, d.jsonPathOfBoolResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the raw response is saved to variable "([^"]*)"$`, d.jsonPathOfRawResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the response is not empty$`, d.jsonPathOfResponseNotEmpty)
	s.Step(`^the JSON path "([^"]*)" of the array response is not empty$`, d.jsonPathOfArrayResponseNotEmpty)
	s.Step(`^the value of the JSON string response is saved to variable "([^"]*)"$`, d.valueOfJSONStringResponseSavedToVar)
	s.Step(`^an HTTP GET is sent to "([^"]*)"$`, d.httpGet)
	s.Step(`^an HTTP GET is sent to "([^"]*)" and the returned status code is (\d+)$`, d.httpGetWithExpectedCode)
	s.Step(`^an HTTP GET is sent to "([^"]*)" signed with KMS key from "([^"]*)"$`, d.httpGetWithSignature)
	s.Step(`^an HTTP GET is sent to "([^"]*)" signed with KMS key from "([^"]*)" and the returned status code is (\d+)$`, d.httpGetWithSignatureAndExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)"$`, d.httpPostFile)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" and the returned status code is (\d+)$`, d.httpPostFileWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)"$`, d.httpPost)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" and the returned status code is (\d+)$`, d.httpPostWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" signed with KMS key from "([^"]*)"$`, d.httpPostWithSignature)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" signed with KMS key from "([^"]*)"$`, d.httpPostFileWithSignature)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" signed with KMS key from "([^"]*)" and the returned status code is (\d+)$`, d.httpPostWithSignatureAndExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" signed with KMS key from "([^"]*)" and the returned status code is (\d+)$`, d.httpPostFileWithSignatureAndExpectedCode)
	s.Step(`^the authorization bearer token for "([^"]*)" requests to path "([^"]*)" is set to "([^"]*)"$`, d.setAuthTokenForPath)
	s.Step(`^variable "([^"]*)" is assigned a unique ID$`, d.setUUIDVariable)
	s.Step(`^domain "([^"]*)" is mapped to "([^"]*)"$`, d.mapHTTPDomain)
	s.Step(`^host-meta document is uploaded to IPNS$`, d.hostMetaDocumentIsUploadedToIPNS)
}
