/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proofs

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("proof-handler")

// Handler implements proof handler (responsible for collecting/managing proofs).
type Handler struct {
	*Providers
	vcCh chan *verifiable.Credential
}

// Providers contains all of the providers required by proof handler.
type Providers struct {
	// TODO: proof store
}

// New returns a new proof handler.
func New(providers *Providers, vcCh chan *verifiable.Credential) *Handler {
	return &Handler{
		Providers: providers,
		vcCh:      vcCh,
	}
}

// RequestProofs requests proofs from witnesses.
func (h *Handler) RequestProofs(vc *verifiable.Credential, witnesses []string) error {
	logger.Debugf("sending anchor credential[%s] to witnesses: %s", vc.ID, witnesses)

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal anchor credential: %s", err.Error())
	}

	retVC, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck())
	if err != nil {
		return fmt.Errorf("failed to parse anchor credential: %s", err.Error())
	}

	// TODO: create an offer for witnesses and wait for witness proofs
	h.vcCh <- retVC

	return nil
}
