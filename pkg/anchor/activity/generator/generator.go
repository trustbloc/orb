/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package generator

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	namespaceVersionDelimiter = "#v"
	minNamespaceVersionParts  = 2
)

type namespaceMap map[string]string

var version = namespaceMap{
	"https://w3id.org/orb":  "did:orb",
	"https://w3id.org/test": "did:test",
}

// CreateGenerator will create generator from namespace and version.
func CreateGenerator(ns string, ver uint64) (string, error) {
	for key, value := range version {
		if value == ns {
			return fmt.Sprintf("%s#v%d", key, ver), nil
		}
	}

	return "", fmt.Errorf("generator not defined for namespace: %s", ns)
}

// ParseNamespaceAndVersion will parse namespace and version from generator.
func ParseNamespaceAndVersion(generator string) (string, uint64, error) {
	parts := strings.Split(generator, namespaceVersionDelimiter)

	if len(parts) != minNamespaceVersionParts {
		return "", 0, fmt.Errorf("invalid namespace and version format: %s", parts)
	}

	ns, ok := version[parts[0]]
	if !ok {
		return "", 0, fmt.Errorf("namespace not defined for generator[%s] string - part[%s]", generator, parts[0])
	}

	ver, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("version has to be an integer: %w", err)
	}

	return ns, uint64(ver), nil
}
