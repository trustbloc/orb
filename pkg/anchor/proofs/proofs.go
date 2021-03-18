/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proofs

import (
	"fmt"
	"net/url"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("proof-handler")

// Handler implements proof handler (responsible for collecting/managing proofs).
type Handler struct {
	*Providers
	vcCh         chan *verifiable.Credential
	apServiceIRI *url.URL
}

// Providers contains all of the providers required by proof handler.
type Providers struct {
	DocLoader ld.DocumentLoader
	// TODO: proof store
}

// New returns a new proof handler.
func New(providers *Providers, vcCh chan *verifiable.Credential, apServiceIRI *url.URL) *Handler {
	return &Handler{
		Providers:    providers,
		vcCh:         vcCh,
		apServiceIRI: apServiceIRI,
	}
}

// RequestProofs requests proofs from witnesses.
func (h *Handler) RequestProofs(vc *verifiable.Credential, witnesses []string) error {
	// TODO: replace hard-coded endpoint with activity pub constant when it becomes available
	systemWitnesses := h.apServiceIRI.String() + "/witnesses"

	// add system witnesses (activity pub collection) to the list of witnesses
	allWitnesses := append(witnesses, systemWitnesses)

	logger.Debugf("sending anchor credential[%s] to witnesses: %s", vc.ID, allWitnesses)

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal anchor credential: %s", err.Error())
	}

	retVC, err := verifiable.ParseCredential(vcBytes, verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.DocLoader))
	if err != nil {
		return fmt.Errorf("failed to parse anchor credential: %s", err.Error())
	}

	// TODO: create an offer for witnesses and wait for witness proofs
	h.vcCh <- retVC

	return nil
}
