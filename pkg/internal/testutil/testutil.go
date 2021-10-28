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
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
	"github.com/trustbloc/orb/pkg/store/expiry"
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
func NewMockURLs(num int, getURI func(i int) string) []*url.URL {
	results := make([]*url.URL, num)

	for i := 0; i < num; i++ {
		results[i] = MustParseURL(getURI(i))
	}

	return results
}

// GetCanonical converts the given JSON string into a canonical JSON.
func GetCanonical(t *testing.T, raw string) string {
	t.Helper()

	var expectedDoc map[string]interface{}

	require.NoError(t, json.Unmarshal([]byte(raw), &expectedDoc))

	bytes, err := canonicalizer.MarshalCanonical(expectedDoc)

	require.NoError(t, err)

	return string(bytes)
}

type provider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// GetLoader returns document loader.
func GetLoader(t *testing.T) *ld.DocumentLoader {
	t.Helper()

	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	require.NoError(t, err)

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	require.NoError(t, err)

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	documentLoader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(ldcontext.MustGetAll()...))
	require.NoError(t, err)

	return documentLoader
}

// GetExpiryService returns test expiry service object. For most tests, the expiry service used doesn't really matter
// this object is just needed to ensure that no nil pointer errors happen when initializing the store.
func GetExpiryService(t *testing.T) *expiry.Service {
	t.Helper()

	coordinationStore, err := mem.NewProvider().OpenStore("coordination")
	require.NoError(t, err)

	return expiry.NewService(time.Second, coordinationStore, "TestInstanceID")
}
