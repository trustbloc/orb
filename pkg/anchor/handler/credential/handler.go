/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"fmt"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
)

var logger = log.New("anchor-credential-handler")

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler struct {
	anchorCh    chan []anchorinfo.AnchorInfo
	casResolver casResolver
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, error)
}

// New creates new credential handler.
func New(anchorCh chan []anchorinfo.AnchorInfo, casResolver casResolver) *AnchorCredentialHandler {
	return &AnchorCredentialHandler{anchorCh: anchorCh, casResolver: casResolver}
}

// HandleAnchorCredential handles anchor credential.
func (h *AnchorCredentialHandler) HandleAnchorCredential(id *url.URL, cid string, anchorCred []byte) error {
	logger.Debugf("Received request: ID [%s], CID [%s], Anchor credential: %s", id, cid, string(anchorCred))

	_, err := h.casResolver.Resolve(id, cid, anchorCred)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor credential: %w", err)
	}

	// TODO: Add hint(s) to anchor credential interface and determine if ipfs or webcas based on hint
	// Since we currently only have cas URLs
	hint := "webcas:" + id.Host

	h.anchorCh <- []anchorinfo.AnchorInfo{{CID: cid, WebCASURL: id, Hint: hint}}

	return nil
}
