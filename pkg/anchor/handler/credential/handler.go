/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"

	casresolver "github.com/trustbloc/orb/pkg/resolver/cas"
)

var logger = log.New("anchor-credential-handler")

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler struct {
	anchorCh    chan []string
	casResolver *casresolver.Resolver
}

// New creates new credential handler.
func New(anchorCh chan []string, casClient casapi.Client, httpClient *http.Client) *AnchorCredentialHandler {
	return &AnchorCredentialHandler{anchorCh: anchorCh, casResolver: casresolver.New(casClient, httpClient)}
}

// HandleAnchorCredential handles anchor credential.
func (h *AnchorCredentialHandler) HandleAnchorCredential(id *url.URL, cid string, anchorCred []byte) error {
	logger.Debugf("Received request: ID [%s], CID [%s], Anchor credential: %s", id, cid, string(anchorCred))

	_, err := h.casResolver.Resolve(id, cid, anchorCred)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor credential: %w", err)
	}

	h.anchorCh <- []string{cid}

	return nil
}
