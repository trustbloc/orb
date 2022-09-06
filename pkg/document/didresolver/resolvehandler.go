/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/document"
)

type webResolver interface {
	ResolveDocument(id string) (*document.ResolutionResult, error)
}

type orbResolver interface {
	ResolveDocument(id string, opts ...document.ResolutionOption) (*document.ResolutionResult, error)
}

// ResolveHandler resolves did:orb and did:web (produced from did:orb) documents.
type ResolveHandler struct {
	webResolver
	orbResolver
}

// NewResolveHandler returns a new did document resolve handler. Supported methods are did:orb and did:web.
func NewResolveHandler(orbResolver orbResolver, webResolver webResolver) *ResolveHandler {
	rh := &ResolveHandler{
		orbResolver: orbResolver,
		webResolver: webResolver,
	}

	return rh
}

// ResolveDocument resolves a did document.
func (r *ResolveHandler) ResolveDocument(id string, opts ...document.ResolutionOption) (*document.ResolutionResult, error) { //nolint:lll
	switch {
	case strings.HasPrefix(id, "did:orb"):
		return r.orbResolver.ResolveDocument(id, opts...)
	case strings.HasPrefix(id, "did:web"):
		return r.webResolver.ResolveDocument(id)
	default:
		return nil, fmt.Errorf("did method not supported for id[%s]", id)
	}
}
