/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// DriverSteps is steps for driver BDD tests.
type DriverSteps struct {
	bddContext *BDDContext
	httpClient *httpClient
}

// NewDriverSteps returns new driver steps.
func NewDriverSteps(ctx *BDDContext, state *state) *DriverSteps {
	return &DriverSteps{
		bddContext: ctx,
		httpClient: newHTTPClient(state, ctx),
	}
}

// RegisterSteps registers agent steps.
func (e *DriverSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^check cli created valid DID through universal resolver$`, e.checkCreatedDID)
}

func (e *DriverSteps) checkCreatedDID() error {
	_, err := e.resolveDIDUniversalResolver(e.bddContext.createdDID)
	if err != nil {
		return err
	}

	return nil
}

func (e *DriverSteps) resolveDIDUniversalResolver(did string) (*ariesdid.DocResolution, error) {
	const maxRetry = 10

	didURL := "http://localhost:8062/1.0/identifiers/" + did

	for i := 1; i <= maxRetry; i++ {
		resp, err := e.httpClient.Get(didURL)

		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 200 {
			return ariesdid.ParseDocumentResolution(resp.Payload)
		}

		if !strings.Contains(resp.ErrorMsg, "DID does not exist") {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, resp.ErrorMsg)
		}

		if i == maxRetry {
			break
		}

		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("DID does not exist")
}
