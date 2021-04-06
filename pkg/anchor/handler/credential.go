/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handler

import (
	"fmt"
	"strings"

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

// HandlerAnchorCredential handles anchor credential.
func (h *AnchorCredentialHandler) HandlerAnchorCredential(id string, anchorCred []byte) error {
	logger.Debugf("received request id[%s], cred: %s", id, string(anchorCred))

	parts := strings.Split(id, "/cas/")

	const numOfParts = 2

	// TODO: will change interface of anchor credential handler to include cid
	// TODO: handle case where anchorCred is nil
	if len(parts) != numOfParts {
		return fmt.Errorf("unable to parse cid: %s", id)
	}

	cid := parts[1]

	h.anchorCh <- []string{cid}

	return nil
}

/*
func unmarshalAnchorCredentialReference(bytes []byte) (*vocab.AnchorCredentialReferenceType, error) {
	r := &vocab.AnchorCredentialReferenceType{}

	if err := json.Unmarshal(bytes, &r); err != nil {
		return nil, err
	}

	return r, nil
} */
