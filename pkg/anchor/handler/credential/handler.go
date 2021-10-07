/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
)

var logger = log.New("anchor-credential-handler")

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

// AnchorEventHandler handles a new, published anchor credential.
type AnchorEventHandler struct {
	anchorPublisher anchorPublisher
	casResolver     casResolver
	maxDelay        time.Duration
	documentLoader  ld.DocumentLoader
	monitoringSvc   monitoringSvc
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, string, error)
}

type anchorPublisher interface {
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
}

// New creates new credential handler.
func New(anchorPublisher anchorPublisher, casResolver casResolver,
	documentLoader ld.DocumentLoader, monitoringSvc monitoringSvc, maxDelay time.Duration) *AnchorEventHandler {
	return &AnchorEventHandler{
		anchorPublisher: anchorPublisher,
		maxDelay:        maxDelay,
		casResolver:     casResolver,
		documentLoader:  documentLoader,
		monitoringSvc:   monitoringSvc,
	}
}

func getUniqueDomainCreated(proofs []verifiable.Proof) []verifiable.Proof {
	var (
		set    = make(map[string]struct{})
		result []verifiable.Proof
	)

	for i := range proofs {
		domain, ok := proofs[i]["domain"].(string)
		if !ok {
			continue
		}

		created, ok := proofs[i]["created"].(string)
		if !ok {
			continue
		}

		if _, ok := set[domain+created]; ok {
			continue
		}

		set[domain+created] = struct{}{}
		set[domain+created] = struct{}{}

		result = append(result, proofs[i])
	}

	return result
}

// HandleAnchorEvent handles an anchor event.
func (h *AnchorEventHandler) HandleAnchorEvent(actor, anchorEventRef *url.URL,
	anchorEvent *vocab.AnchorEventType) error {
	logger.Debugf("Received request from [%s] for anchor event URL [%s]", actor, anchorEventRef)

	var err error

	var anchorEventBytes []byte

	if anchorEvent != nil {
		anchorEventBytes, err = canonicalizer.MarshalCanonical(anchorEvent)
		if err != nil {
			return fmt.Errorf("marshal anchor event: %w", err)
		}
	}

	anchorEventBytes, localHL, err := h.casResolver.Resolve(nil, anchorEventRef.String(), anchorEventBytes)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor credential: %w", err)
	}

	if anchorEvent == nil {
		anchorEvent = &vocab.AnchorEventType{}

		err = json.Unmarshal(anchorEventBytes, anchorEvent)
		if err != nil {
			return fmt.Errorf("unmarshal anchor event: %w", err)
		}
	}

	vc, err := util.VerifiableCredentialFromAnchorEvent(anchorEvent,
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(h.documentLoader),
	)
	if err != nil {
		return fmt.Errorf("failed get verifiable credential from anchor event: %w", err)
	}

	for _, proof := range getUniqueDomainCreated(vc.Proofs) {
		// getUniqueDomainCreated already checked that data is a string
		domain := proof["domain"].(string)   // nolint: errcheck, forcetypeassert
		created := proof["created"].(string) // nolint: errcheck, forcetypeassert

		createdTime, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return fmt.Errorf("parse created: %w", err)
		}

		err = h.monitoringSvc.Watch(vc, time.Now().Add(h.maxDelay), domain, createdTime)
		if err != nil {
			return fmt.Errorf("failed to setup monitoring for anchor credential[%s]: %w", vc.ID, err)
		}
	}

	return h.anchorPublisher.PublishAnchor(
		&anchorinfo.AnchorInfo{
			Hashlink:      anchorEventRef.String(),
			LocalHashlink: localHL,
			AttributedTo:  actor.String(),
		},
	)
}
