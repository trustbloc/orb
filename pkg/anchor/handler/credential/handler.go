/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("anchor-credential-handler")

// New creates new credential handler.
func New(anchorCh chan []string) *AnchorCredentialHandler {
	return &AnchorCredentialHandler{anchorCh: anchorCh}
}

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler struct {
	anchorCh chan []string
}

// HandleAnchorCredential handles anchor credential.
func (h *AnchorCredentialHandler) HandleAnchorCredential(id *url.URL, cid string, anchorCred []byte) error {
	logger.Debugf("received request id[%s], cid[%s], cred: %s", id, cid, string(anchorCred))

	h.anchorCh <- []string{cid}

	return nil
}
