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
	"path/filepath"
	"strconv"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// CommonSteps contain BDDContext
type CommonSteps struct {
	BDDContext *BDDContext
	state      *state
}

// NewCommonSteps create new CommonSteps struct
func NewCommonSteps(context *BDDContext, state *state) *CommonSteps {
	return &CommonSteps{
		BDDContext: context,
		state:      state,
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

func (d *CommonSteps) responseEquals(value string) error {
	if d.state.getResponse() == value {
		logger.Infof("Response equals expected value [%s]", value)
		return nil
	}

	return fmt.Errorf("Reponse [%s] does not equal expected value [%s]", d.state.getResponse(), value)
}

func (d *CommonSteps) httpGetWithExpectedCode(url string, expectingCode int) error {
	_, code, _, err := d.doHTTPGet(url)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpGet(url string) error {
	d.state.clearResponse()

	payload, code, _, err := d.doHTTPGet(url)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) httpGetWithSignature(url, privKeyFile, pubKeyID string) error {
	d.state.clearResponse()

	payload, code, _, err := d.doHTTPGetWithSignature(url, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) httpGetWithSignatureAndExpectedCode(url, privKeyFile, pubKeyID string, expectingCode int) error {
	_, code, _, err := d.doHTTPGetWithSignature(url, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpPostFile(url, path string) error {
	_, code, _, err := d.doHTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	return nil
}

func (d *CommonSteps) httpPostFileWithExpectedCode(url, path string, expectingCode int) error {
	_, code, _, err := d.doHTTPPostFile(url, path)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpPostFileWithSignature(url, path, privKeyFile, pubKeyID string) error {
	_, code, _, err := d.doHTTPPostFileWithSignature(url, path, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	return nil
}

func (d *CommonSteps) httpPostFileWithSignatureAndExpectedCode(url, path, privKeyFile, pubKeyID string, expectingCode int) error {
	_, code, _, err := d.doHTTPPostFileWithSignature(url, path, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	return nil
}

func (d *CommonSteps) httpPost(url, data, contentType string) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	payload, code, _, err := d.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) httpPostWithSignature(url, data, contentType, privKeyFile, pubKeyID string) error {
	d.state.clearResponse()

	err := d.state.resolveVarsInExpression(&data, &privKeyFile, &pubKeyID)
	if err != nil {
		return err
	}

	payload, code, _, err := d.doHTTPPostWithSignature(url, []byte(data), contentType, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("received status code %d", code)
	}

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) httpPostWithExpectedCode(url, data, contentType string, expectingCode int) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	payload, code, _, err := d.doHTTPPost(url, []byte(data), contentType)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) httpPostWithSignatureAndExpectedCode(url, data, contentType, privKeyFile, pubKeyID string, expectingCode int) error {
	d.state.clearResponse()

	resolved, err := d.state.resolveVars(data)
	if err != nil {
		return err
	}

	data = resolved.(string)

	payload, code, _, err := d.doHTTPPostWithSignature(url, []byte(data), contentType, privKeyFile, pubKeyID)
	if err != nil {
		return err
	}

	if code != expectingCode {
		return fmt.Errorf("expecting status code %d but got %d", expectingCode, code)
	}

	logger.Infof("Returned status code is %d which is the expected status code", code)

	d.state.setResponse(string(payload))

	return nil
}

func (d *CommonSteps) doHTTPGet(url string) ([]byte, int, http.Header, error) {
	client := newHTTPClient(d.state)

	resolved, err := d.state.resolveVars(url)
	if err != nil {
		return nil, 0, nil, err
	}

	payload, statusCode, header, err := client.Get(resolved.(string))
	if err != nil {
		return nil, 0, nil, err
	}

	printResponse(statusCode, payload, header)

	return payload, statusCode, header, nil
}

func (d *CommonSteps) doHTTPGetWithSignature(url, privKeyFile, pubKeyID string) ([]byte, int, http.Header, error) {
	client := newHTTPClient(d.state)

	err := d.state.resolveVarsInExpression(&url, &privKeyFile, &pubKeyID)
	if err != nil {
		return nil, 0, nil, err
	}

	payload, statusCode, header, err := client.GetWithSignature(url, privKeyFile, pubKeyID)
	if err != nil {
		return nil, 0, nil, err
	}

	printResponse(statusCode, payload, header)

	return payload, statusCode, header, nil
}

func (d *CommonSteps) doHTTPPost(url string, content []byte, contentType string) ([]byte, int, http.Header, error) {
	client := newHTTPClient(d.state)

	resolved, err := d.state.resolveVars(url)
	if err != nil {
		return nil, 0, nil, err
	}

	payload, statusCode, header, err := client.Post(resolved.(string), content, contentType)
	if err != nil {
		return nil, 0, nil, err
	}

	printResponse(statusCode, payload, header)

	return payload, statusCode, header, nil
}

func (d *CommonSteps) doHTTPPostWithSignature(url string, content []byte, contentType, privKeyFile, pubKeyID string) ([]byte, int, http.Header, error) {
	client := newHTTPClient(d.state)

	err := d.state.resolveVarsInExpression(&url, &privKeyFile, &pubKeyID)
	if err != nil {
		return nil, 0, nil, err
	}

	payload, statusCode, header, err := client.PostWithSignature(url, content, contentType, privKeyFile, pubKeyID)
	if err != nil {
		return nil, 0, nil, err
	}

	printResponse(statusCode, payload, header)

	return payload, statusCode, header, nil
}

func (d *CommonSteps) doHTTPPostFile(url, path string) ([]byte, int, http.Header, error) {
	return d.doHTTPPostFileWithSignature(url, path, "", "")
}

func (d *CommonSteps) doHTTPPostFileWithSignature(url, path, privKeyFile, pubKeyID string) ([]byte, int, http.Header, error) {
	d.state.clearResponse()

	logger.Infof("Uploading file [%s] to [%s]", path, url)

	contentType, err := contentTypeFromFileName(path)
	if err != nil {
		return nil, 0, nil, err
	}

	contents, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, 0, nil, err
	}

	payload, statusCode, header, err := d.doHTTPPostWithSignature(url, contents, contentType, privKeyFile, pubKeyID)
	if err != nil {
		return nil, 0, nil, err
	}

	d.state.setResponse(string(payload))

	return payload, statusCode, header, nil
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

	logger.Infof("Setting authorization bearer token for [%s] (%s) to [%s]", path, method, token)

	d.state.setAuthToken(path, method, token)

	return nil
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
	s.Step(`^the JSON path "([^"]*)" of the numeric response equals "([^"]*)"$`, d.jsonPathOfNumericResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the boolean response equals "([^"]*)"$`, d.jsonPathOfBoolResponseEquals)
	s.Step(`^the JSON path "([^"]*)" of the response has (\d+) items$`, d.jsonPathOfResponseHasNumItems)
	s.Step(`^the JSON path "([^"]*)" of the response contains "([^"]*)"$`, d.jsonPathOfResponseContains)
	s.Step(`^the JSON path "([^"]*)" of the response does not contain "([^"]*)"$`, d.jsonPathOfResponseNotContains)
	s.Step(`^the JSON path "([^"]*)" of the response is saved to variable "([^"]*)"$`, d.jsonPathOfResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the numeric response is saved to variable "([^"]*)"$`, d.jsonPathOfNumericResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the boolean response is saved to variable "([^"]*)"$`, d.jsonPathOfBoolResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the raw response is saved to variable "([^"]*)"$`, d.jsonPathOfRawResponseSavedToVar)
	s.Step(`^the JSON path "([^"]*)" of the response is not empty$`, d.jsonPathOfResponseNotEmpty)
	s.Step(`^the JSON path "([^"]*)" of the array response is not empty$`, d.jsonPathOfArrayResponseNotEmpty)
	s.Step(`^an HTTP GET is sent to "([^"]*)"$`, d.httpGet)
	s.Step(`^an HTTP GET is sent to "([^"]*)" and the returned status code is (\d+)$`, d.httpGetWithExpectedCode)
	s.Step(`^an HTTP GET is sent to "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)"$`, d.httpGetWithSignature)
	s.Step(`^an HTTP GET is sent to "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)" and the returned status code is (\d+)$`, d.httpGetWithSignatureAndExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)"$`, d.httpPostFile)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" and the returned status code is (\d+)$`, d.httpPostFileWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)"$`, d.httpPost)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" and the returned status code is (\d+)$`, d.httpPostWithExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)"$`, d.httpPostWithSignature)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)"$`, d.httpPostFileWithSignature)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content "([^"]*)" of type "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)" and the returned status code is (\d+)$`, d.httpPostWithSignatureAndExpectedCode)
	s.Step(`^an HTTP POST is sent to "([^"]*)" with content from file "([^"]*)" signed with private key from file "([^"]*)" using key ID "([^"]*)" and the returned status code is (\d+)$`, d.httpPostFileWithSignatureAndExpectedCode)
	s.Step(`^the authorization bearer token for "([^"]*)" requests to path "([^"]*)" is set to "([^"]*)"$`, d.setAuthTokenForPath)
	s.Step(`^variable "([^"]*)" is assigned a unique ID$`, d.setUUIDVariable)
}
