/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/trustbloc/orb/pkg/hashlink"
)

const (
	funcHashLinkPrefix   = "$hashlink(|"
	resourceHashProperty = "ResourceHash"
)

type httpPath = string
type httpMethod = string
type authToken = string

type state struct {
	vars          map[string]string
	responseValue string
	authTokenMap  map[httpPath]map[httpMethod]authToken
}

func newState() *state {
	vars := make(map[string]string)

	// Add environment variables.
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		vars[pair[0]] = pair[1]
	}

	return &state{
		vars:         vars,
		authTokenMap: make(map[httpPath]map[httpMethod]authToken),
	}
}

// clearState clears all global variables
func (s *state) clear() {
	s.vars = make(map[string]string)

	// Add environment variables.
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		s.vars[pair[0]] = pair[1]
	}

	s.authTokenMap = make(map[httpPath]map[httpMethod]authToken)
	s.responseValue = ""
}

// clearResponse clears the query response
func (s *state) clearResponse() {
	s.responseValue = ""
}

func (s *state) setResponse(response string) {
	s.responseValue = response
}

// getResponse returns the most recent response
func (s *state) getResponse() string {
	return s.responseValue
}

func (s *state) setAuthToken(path httpPath, method httpMethod, token authToken) {
	tokensForPath, ok := s.authTokenMap[path]
	if !ok {
		tokensForPath = make(map[httpMethod]authToken)
		s.authTokenMap[path] = tokensForPath
	}

	tokensForPath[method] = token
}

func (s *state) getAuthToken(path httpPath, method httpMethod) authToken {
	return s.authTokenMap[path][method]
}

// setVar sets the value for the given variable
func (s *state) setVar(varName, value string) {
	s.vars[varName] = value
}

// getVar gets the value for the given variable
// Returns true if the variable exists; false otherwise
func (s *state) getVar(varName string) (string, bool) {
	value, ok := s.vars[varName]
	return value, ok
}

// resolve resolves all variables within the given arg
//
// Example 1: Simple variable
// 	Given:
// 		vars = {
// 			"var1": "value1",
// 			"var2": "value2",
// 			}
//	Then:
//		"${var1}" = "value1"
//		"X_${var1}_${var2} = "X_value1_value2
//
// Example 2: Array variable
// 	Given:
// 		vars = {
// 			"arr1": "value1,value2,value3",
// 			}
//	Then:
//		"${arr1[0]_arr1[1]_arr1[2]}" = "value1_value2_value3"
//
func (s *state) resolve(arg string) (string, error) {
	return s.resolveWithPrefix("$", arg)
}

func (s *state) resolveWithPrefix(prefix, arg string) (string, error) {
	for {
		logger.Debugf("Resolving vars for %s", arg)

		str, err := doResolve(s.vars, prefix, arg)
		if err != nil {
			return arg, err
		}
		if str == arg {
			// Done
			return s.evaluateFunctions(str)
		}
		arg = str
	}
}

func (s *state) resolveAll(args []string) ([]string, error) {
	argArr := make([]string, len(args))
	for i, arg := range args {
		v, err := s.resolve(arg)
		if err != nil {
			return nil, err
		}
		argArr[i] = v
	}
	return argArr, nil
}

func doResolve(vars map[string]string, prefix, arg string) (string, error) {
	if len(arg) <= 3 {
		return arg, nil
	}

	open := strings.Index(arg, fmt.Sprintf("%s{", prefix))
	if open == -1 {
		return arg, nil
	}

	close := strings.Index(arg[open+2:], "}")
	if close == -1 {
		return arg, fmt.Errorf("expecting } for arg '%s'", arg)
	}

	close = close + open + 2

	// Check for array
	varName := arg[open+2 : close]
	ob := strings.Index(varName, "[")
	if ob == -1 {
		// Not an array
		return replace(arg, vars[varName], open, close), nil
	}

	cb := strings.Index(varName, "]")
	if cb == -1 {
		return arg, fmt.Errorf("invalid arg '%s'", arg)
	}

	arrVar := varName[0:ob]
	values := vars[arrVar]

	if values == "" {
		return replace(arg, "", open, close), nil
	}

	index := varName[ob+1 : cb]

	vals := strings.Split(values, ",")
	i, err := strconv.Atoi(index)
	if err != nil {
		return arg, fmt.Errorf("invalid index [%s] for arg '%s'", index, arg)
	}

	if i >= len(vals) {
		return arg, fmt.Errorf("index [%d] out of range for arg '%s'", i, arg)
	}

	return replace(arg, vals[i], open, close), nil
}

func replace(arg, value string, open, close int) string {
	return arg[0:open] + value + arg[close+1:]
}

// resolveVars resolves all variables within the given value. The value
// may be one of the following types:
// - string
// - []interface{}
// - map[string]interface{}
// All other types will return with no resolution
func (s *state) resolveVars(val interface{}) (interface{}, error) {
	switch v := val.(type) {
	case string:
		val, err := s.resolve(v)
		if err != nil {
			return nil, err
		}
		return val, nil

	case []interface{}:
		val, err := s.resolveArray(v)
		if err != nil {
			return nil, err
		}
		return val, nil

	case map[string]interface{}:
		val, err := s.resolveMap(v)
		if err != nil {
			return nil, err
		}
		return val, nil

	default:
		return val, nil
	}
}

// resolveVars resolves all variables within the given expressions
// Example:
//
// Given:
//   var1 = "variable1"
//   var2 = "variable2"
//
// value1 := "This is ${var1}"
// value2 := "This is ${var2}
//
// err := resolveVarsInExpression(&value1, &value2)
//
// Result:
//   value1 = "This is variable1"
//   value2 = "This is variable2"
func (s *state) resolveVarsInExpression(expressions ...*string) error {
	for _, expr := range expressions {
		resolved, err := s.resolveVars(*expr)
		if err != nil {
			return err
		}

		*expr = resolved.(string)
	}

	return nil
}

func (s *state) resolveMap(doc map[string]interface{}) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	for field, val := range doc {
		val, err := s.resolveVars(val)
		if err != nil {
			return nil, fmt.Errorf("error resolving field [%s]: %w", field, err)
		}
		m[field] = val
	}
	return m, nil
}

func (s *state) resolveArray(arr []interface{}) ([]interface{}, error) {
	resolved := make([]interface{}, len(arr))
	for i, v := range arr {
		val, err := s.resolveVars(v)
		if err != nil {
			return nil, fmt.Errorf("error resolving array element %d: %w", i, err)
		}
		resolved[i] = val
	}
	return resolved, nil
}

func (s *state) evaluateFunctions(expression string) (string, error) {
	switch {
	case strings.Contains(expression, funcHashLinkPrefix):
		return s.evaluateHashlinkFunc(expression)
	default:
		return expression, nil
	}
}

func (s *state) evaluateHashlinkFunc(expression string) (string, error) {
	i := strings.Index(expression, "|)")
	if i < 0 {
		return expression, nil
	}

	propertyExp := expression[i:]

	j := strings.Index(propertyExp, ".")
	if j < 0 {
		return "", errors.New("no hashlink property specified")
	}

	property := propertyExp[j+1:]

	hl := expression[len(funcHashLinkPrefix):i]

	hlParser := hashlink.New()

	hlInfo, err := hlParser.ParseHashLink(hl)
	if err != nil {
		return "", err
	}

	switch property {
	case resourceHashProperty:
		logger.Infof("Evaluated property [%s] of hashlink [%s]: [%s]", property, hl, hlInfo.ResourceHash)

		return hlInfo.ResourceHash, nil
	default:
		return "", fmt.Errorf("invalid hashlink property [%s]", property)
	}
}
