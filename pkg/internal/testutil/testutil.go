/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

// MustParseURL parses the given string and returns the URL.
// If the given string is not a valid URL then the function panics.
func MustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}

// NewMockID returns a URL using the base IRI and the given path.
func NewMockID(iri fmt.Stringer, path string) *url.URL {
	return MustParseURL(fmt.Sprintf("%s%s", iri, path))
}

// NewMockURLs returns the given number of URLs using the given function to format each one.
//nolint:unparam
func NewMockURLs(num int, getURI func(i int) string) []*url.URL {
	results := make([]*url.URL, num)

	for i := 0; i < num; i++ {
		results[i] = MustParseURL(getURI(i))
	}

	return results
}

// GetCanonical converts the given JSON string into a canonical JSON.
func GetCanonical(t *testing.T, raw string) string {
	var expectedDoc map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(raw), &expectedDoc))

	bytes, err := canonicalizer.MarshalCanonical(expectedDoc)

	require.NoError(t, err)

	return string(bytes)
}
