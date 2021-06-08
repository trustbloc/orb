/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credential

import (
	"fmt"
	"net/url"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
)

var logger = log.New("anchor-credential-handler")

type monitoringSvc interface {
	Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error
}

// AnchorCredentialHandler handles a new, published anchor credential.
type AnchorCredentialHandler struct {
	anchorPublisher anchorPublisher
	casResolver     casResolver
	maxDelay        time.Duration
	documentLoader  ld.DocumentLoader
	monitoringSvc   monitoringSvc
}

type casResolver interface {
	Resolve(webCASURL *url.URL, cid string, data []byte) ([]byte, error)
}

type anchorPublisher interface {
	PublishAnchor(anchor *anchorinfo.AnchorInfo) error
}

// New creates new credential handler.
func New(anchorPublisher anchorPublisher, casResolver casResolver,
	documentLoader ld.DocumentLoader, monitoringSvc monitoringSvc, maxDelay time.Duration) *AnchorCredentialHandler {
	return &AnchorCredentialHandler{
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

// HandleAnchorCredential handles anchor credential.
func (h *AnchorCredentialHandler) HandleAnchorCredential(id *url.URL, cid string, anchorCred []byte) error {
	logger.Debugf("Received request: ID [%s], CID [%s], Anchor credential: %s", id, cid, string(anchorCred))

	newCred, err := h.casResolver.Resolve(id, cid, anchorCred)
	if err != nil {
		return fmt.Errorf("failed to resolve anchor credential: %w", err)
	}

	credentialsToMonitor := anchorCred
	if len(credentialsToMonitor) == 0 || (string(credentialsToMonitor) == "null") {
		credentialsToMonitor = newCred
	}

	if len(credentialsToMonitor) != 0 && (string(credentialsToMonitor) != "null") {
		vc, err := verifiable.ParseCredential(credentialsToMonitor,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(h.documentLoader),
		)
		if err != nil {
			return fmt.Errorf("failed to parse credential: %w", err)
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
	}

	// TODO: Add hint(s) to anchor credential interface and determine if ipfs or webcas based on hint
	// Since we currently only have cas URLs
	hint := "webcas:" + id.Host

	return h.anchorPublisher.PublishAnchor(&anchorinfo.AnchorInfo{CID: cid, WebCASURL: id, Hint: hint})
}
