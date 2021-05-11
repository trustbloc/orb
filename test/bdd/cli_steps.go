/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cucumber/godog"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/orb/test/bdd/restclient"
)

// Steps is steps for cli BDD tests.
type Steps struct {
	bddContext *BDDContext
	cliValue   string
	createdDID *ariesdid.Doc
}

// NewCLISteps returns new agent from client SDK.
func NewCLISteps(ctx *BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Orb DID is created through cli$`, e.createDID)
	s.Step(`^Orb DID is updated through cli$`, e.updateDID)
	s.Step(`^Orb DID is recovered through cli$`, e.recoverDID)
	s.Step(`^Orb DID is deactivated through cli$`,
		e.deactivateDID)
	s.Step(`^check cli created valid DID$`, e.checkCreatedDID)
	s.Step(`^check cli recovered DID$`, e.checkRecoveredDID)
	s.Step(`^check cli deactivated DID$`, e.checkDeactivatedDID)
	s.Step(`^check cli updated DID$`, e.checkUpdatedDID)
}

func (e *Steps) checkCreatedDID() error {
	const numberOfVerificationMethods = 2

	const numberOfServices = 2

	doc, err := ariesdid.ParseDocument([]byte(e.cliValue))
	if err != nil {
		return err
	}

	result, err := e.resolveDID(doc.ID)
	if err != nil {
		return err
	}

	if len(result.DIDDocument.VerificationMethod) != numberOfVerificationMethods {
		return fmt.Errorf("did doc verification method is not equal to %d", numberOfVerificationMethods)
	}

	if len(result.DIDDocument.Service) != numberOfServices {
		return fmt.Errorf("did doc services is not equal to %d", numberOfServices)
	}

	e.createdDID = result.DIDDocument

	return nil
}

func (e *Steps) checkRecoveredDID() error {
	const numberOfVerificationMethods = 1

	const numberOfServices = 1

	const maxRetry = 10

	for i := 1; i <= maxRetry; i++ {

		result, err := e.resolveDID(e.createdDID.ID)
		if err != nil {
			return err
		}

		doc := result.DIDDocument

		if len(doc.VerificationMethod) != numberOfVerificationMethods {
			if i == maxRetry {
				return fmt.Errorf("did doc verification method is not equal to %d", numberOfVerificationMethods)
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if len(doc.Service) != numberOfServices {
			if i == maxRetry {
				return fmt.Errorf("did doc services is not equal to %d", numberOfServices)
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if !strings.Contains(doc.VerificationMethod[0].ID, "key-recover-id") {
			if i == maxRetry {
				return fmt.Errorf("wrong recoverd verification method")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if !strings.Contains(doc.Service[0].ID, "svc-recover-id") {
			if i == maxRetry {
				return fmt.Errorf("wrong recoverd service")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		return nil
	}

	return fmt.Errorf("recover failed")
}

func (e *Steps) resolveDID(did string) (*ariesdid.DocResolution, error) {
	const maxRetry = 10

	for i := 1; i <= maxRetry; i++ {
		resp, err := restclient.SendResolveRequest("https://localhost:48326/sidetree/v1/identifiers/" + did)

		if err == nil && resp.StatusCode == 200 {
			return ariesdid.ParseDocumentResolution(resp.Payload)
		}

		if err != nil || resp.StatusCode != 404 || i == maxRetry {
			return nil, err
		}

		time.Sleep(1 * time.Second)
	}

	return nil, fmt.Errorf("DID does not exist")
}

func (e *Steps) checkDeactivatedDID() error {
	const maxRetry = 10

	for i := 1; i <= maxRetry; i++ {
		result, err := e.resolveDID(e.createdDID.ID)
		if err != nil {
			return err
		}

		if !result.DocumentMetadata.Deactivated {
			if i == maxRetry {
				return fmt.Errorf("document has not been deactivated - deactivated flag is false")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		return nil
	}

	return fmt.Errorf("document has not been deactivated ")
}

func (e *Steps) checkUpdatedDID() error { //nolint: gocyclo
	const numberOfVerificationMethods = 2

	const numberOfServices = 1

	const maxRetry = 10

	for i := 1; i <= maxRetry; i++ {
		result, err := e.resolveDID(e.createdDID.ID)
		if err != nil {
			return err
		}

		doc := result.DIDDocument

		if len(doc.VerificationMethod) != numberOfVerificationMethods {
			if i == maxRetry {
				return fmt.Errorf("did doc verification method is not equal to %d", numberOfVerificationMethods)
			}

			time.Sleep(1 * time.Second)

			continue
		}

		key2ID := "key2"
		key3ID := "key3"
		svc3ID := "svc3"

		key2Exist := false
		key3Exist := false

		if len(doc.CapabilityInvocation) != 1 {
			if i == maxRetry {
				return fmt.Errorf("did capability invocation is not equal to 1")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if !strings.Contains(doc.CapabilityInvocation[0].VerificationMethod.ID, key2ID) {
			if i == maxRetry {
				return fmt.Errorf("wrong capability invocation key")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		for _, v := range doc.VerificationMethod {
			if strings.Contains(v.ID, key2ID) {
				key2Exist = true
				continue
			}

			if strings.Contains(v.ID, key3ID) {
				key3Exist = true
				continue
			}
		}

		if !key2Exist || !key3Exist {
			if i == maxRetry {
				return fmt.Errorf("wrong updated verification method")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if len(doc.Service) != numberOfServices {
			if i == maxRetry {
				return fmt.Errorf("did doc services is not equal to %d", numberOfServices)
			}

			time.Sleep(1 * time.Second)

			continue
		}

		if !strings.Contains(doc.Service[0].ID, svc3ID) {
			if i == maxRetry {
				return fmt.Errorf("wrong updated service")
			}

			time.Sleep(1 * time.Second)

			continue
		}

		return nil
	}

	return fmt.Errorf("update failed")
}

func (e *Steps) updateDID() error {
	var args []string

	args = append(args, "did", "update",
		"--sidetree-url-operation", "https://localhost:48326/sidetree/v1/operations",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--did-uri", e.createdDID.ID, "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--add-publickey-file", "fixtures/did-keys/update/publickeys.json",
		"--sidetree-write-token", "rw_token", "--signingkey-file", "./fixtures/keys/update/key_encrypted.pem",
		"--signingkey-password", "123", "--nextupdatekey-file", "./fixtures/keys/update2/public.pem",
		"--add-service-file", "fixtures/did-services/update/services.json")

	value, err := execCMD(args...)

	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) recoverDID() error {
	var args []string

	args = append(args,
		"did", "recover",
		"--sidetree-url-operation", "https://localhost:48326/sidetree/v1/operations",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--did-anchor-origin", "https://orb.domain2.com/services/orb",
		"--did-uri", e.createdDID.ID, "--signingkey-password", "123",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--publickey-file", "fixtures/did-keys/recover/publickeys.json", "--sidetree-write-token", "rw_token",
		"--service-file", "fixtures/did-services/recover/services.json",
		"--nextrecoverkey-file", "./fixtures/keys/recover2/public.pem", "--nextupdatekey-file",
		"./fixtures/keys/update3/public.pem", "--signingkey-file", "./fixtures/keys/recover/key_encrypted.pem")

	value, err := execCMD(args...)

	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) deactivateDID() error {
	var args []string

	args = append(args, "did", "deactivate",
		"--sidetree-url-operation", "https://localhost:48326/sidetree/v1/operations",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--did-uri", e.createdDID.ID, "--signingkey-password", "123",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem", "--sidetree-write-token", "rw_token",
		"--signingkey-file", "./fixtures/keys/recover2/key_encrypted.pem")

	value, err := execCMD(args...)

	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) createDID() error {
	var args []string

	args = append(args, "did", "create", "--did-anchor-origin", "https://orb.domain2.com/services/orb",
		"--sidetree-url", "https://localhost:48326/sidetree/v1/operations", "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--publickey-file", "fixtures/did-keys/create/publickeys.json",
		"--sidetree-write-token", "rw_token", "--service-file", "fixtures/did-services/create/services.json",
		"--recoverykey-file", "./fixtures/keys/recover/public.pem", "--updatekey-file", "./fixtures/keys/update/public.pem")

	value, err := execCMD(args...)

	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func execCMD(args ...string) (string, error) {
	cmd := exec.Command(fmt.Sprintf("../../.build/extract/orb-cli-%s-amd64", runtime.GOOS), args...) // nolint: gosec

	var out bytes.Buffer

	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}

	return out.String(), nil
}
