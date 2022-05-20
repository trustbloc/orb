/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/cucumber/godog"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

type createKeystoreReq struct {
	Controller string `json:"controller"`
}

type createKeyStoreResp struct {
	KeyStoreURL string `json:"key_store_url"`
}

type createKeyReq struct {
	KeyType   string `json:"key_type"`
	ExportKey bool   `json:"export"`
}

type createKeyResp struct {
	KeyURL    string `json:"key_url"`
	PublicKey []byte `json:"public_key"`
}

// Steps is steps for cli BDD tests.
type Steps struct {
	bddContext *BDDContext
	state      *state

	cliValue      string
	createdDID    *ariesdid.Doc
	httpClient    *httpClient
	keyStoreURL   string
	updateKeyID   string
	recoverKeyID  string
	recover2KeyID string
	update2KeyID  string
	update3KeyID  string
}

// NewCLISteps returns new agent from client SDK.
func NewCLISteps(ctx *BDDContext, state *state) *Steps {
	return &Steps{
		bddContext: ctx,
		state:      state,
		httpClient: newHTTPClient(state, ctx),
	}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Create keys in kms$`, e.setupKeys)
	s.Step(`^Orb DID is created through cli$`, e.createDID)
	s.Step(`^Orb DID is resolved through cli$`, e.cliResolveDID)
	s.Step(`^Orb DID is updated through cli$`, e.updateDID)
	s.Step(`^Orb DID is recovered through cli$`, e.recoverDID)
	s.Step(`^Orb DID is deactivated through cli$`,
		e.deactivateDID)
	s.Step(`^check cli created valid DID$`, e.checkCreatedDID)
	s.Step(`^check cli recovered DID$`, e.checkRecoveredDID)
	s.Step(`^check cli deactivated DID$`, e.checkDeactivatedDID)
	s.Step(`^check cli updated DID$`, e.checkUpdatedDID)
	s.Step(`^user create "([^"]*)" activity with outbox-url "([^"]*)" actor "([^"]*)" to "([^"]*)" action "([^"]*)"$`, e.createActivity)
	s.Step(`^orb-cli is executed with args '([^']*)'$`, e.execute)
}

func (e *Steps) setupKeys() error {
	request := &createKeystoreReq{
		Controller: "did:example:123456",
	}

	response := &createKeyStoreResp{}

	err := sendHTTPRequest(e.httpClient.client, request, nil, http.MethodPost,
		"http://localhost:7878/v1/keystores", response)
	if err != nil {
		return err
	}

	e.keyStoreURL = strings.ReplaceAll(response.KeyStoreURL, "orb.kms", "localhost")

	e.updateKeyID, err = e.createKey("ED25519")
	if err != nil {
		return err
	}

	e.recoverKeyID, err = e.createKey("ECDSAP256IEEEP1363")
	if err != nil {
		return err
	}

	e.update2KeyID, err = e.createKey("ED25519")
	if err != nil {
		return err
	}

	e.recover2KeyID, err = e.createKey("ED25519")
	if err != nil {
		return err
	}

	e.update3KeyID, err = e.createKey("ED25519")
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) createKey(keyType string) (string, error) {
	createKeyR := &createKeyReq{
		KeyType:   keyType,
		ExportKey: true,
	}

	createKeyRes := &createKeyResp{}

	err := sendHTTPRequest(e.httpClient.client, createKeyR, nil, http.MethodPost,
		fmt.Sprintf("%s/%s", e.keyStoreURL, "keys"), createKeyRes)
	if err != nil {
		return "", err
	}

	parts := strings.Split(createKeyRes.KeyURL, "/")

	return parts[len(parts)-1], nil
}

func (e *Steps) checkCreatedDID() error {
	const numberOfVerificationMethods = 3

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

func (e *Steps) cliResolveDID() error {
	var args []string

	args = append(args, "did", "resolve",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--did-uri", e.createdDID.ID, "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--auth-token", "ADMIN_TOKEN", "--verify-resolution-result-type", "all")

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.state.setResponse(value)

	if strings.Contains(value, e.createdDID.ID) {
		return nil
	}

	return fmt.Errorf(value)
}

func (e *Steps) resolveDID(did string) (*ariesdid.DocResolution, error) {
	const maxRetry = 10

	didURL := "https://localhost:48326/sidetree/v1/identifiers/" + did

	for i := 1; i <= maxRetry; i++ {
		resp, err := e.httpClient.Get(didURL)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == 200 {
			return ariesdid.ParseDocumentResolution(resp.Payload)
		}

		if resp.StatusCode != 404 {
			return nil, fmt.Errorf("%d: %s", resp.StatusCode, resp.ErrorMsg)
		}

		if i == maxRetry {
			break
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

func (e *Steps) createActivity(subCmd, outboxURL, actor, to, action string) error {
	var args []string

	args = append(args, subCmd,
		"--outbox-url", outboxURL,
		"--actor", actor,
		"--to", to,
		"--action", action,
		"--max-retry", "3",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--auth-token", "ADMIN_TOKEN",
	)

	if action == "Undo" {
		if subCmd == "follower" {
			s := strings.Split(e.cliValue, "Follow id: ")
			id := s[1][1 : len(s[1])-2]
			args = append(args, "--follow-id", id)
		} else {
			s := strings.Split(e.cliValue, "InviteWitness id: ")
			id := s[1][1 : len(s[1])-2]
			args = append(args, "--invite-witness-id", id)
		}
	}

	value, err := execCMD(args...)
	if err != nil && !strings.Contains(err.Error(), "no such host") &&
		!strings.Contains(err.Error(), "connection timed out") &&
		!strings.Contains(err.Error(), "remote error") &&
		!strings.Contains(err.Error(), "certificate signed by unknown authority") {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) updateDID() error {
	var args []string

	args = append(args, "did", "update",
		"--sidetree-url-operation", "https://localhost:48326/sidetree/v1/operations",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--kms-store-endpoint", e.keyStoreURL,
		"--did-uri", e.createdDID.ID, "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--add-publickey-file", "fixtures/did-keys/update/publickeys.json",
		"--sidetree-write-token", "ADMIN_TOKEN", "--signingkey-id", e.updateKeyID,
		"--nextupdatekey-id", e.update2KeyID,
		"--add-service-file", "fixtures/did-services/update/services.json")

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.cliValue = value

	e.state.setResponse(value)

	return nil
}

func (e *Steps) recoverDID() error {
	var args []string

	args = append(args,
		"did", "recover",
		"--sidetree-url-operation", "https://localhost:48326/sidetree/v1/operations",
		"--sidetree-url-resolution", "https://localhost:48326/sidetree/v1/identifiers",
		"--did-anchor-origin", "https://orb.domain1.com", "--kms-store-endpoint", e.keyStoreURL,
		"--did-uri", e.createdDID.ID, "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--publickey-file", "fixtures/did-keys/recover/publickeys.json", "--sidetree-write-token", "ADMIN_TOKEN",
		"--service-file", "fixtures/did-services/recover/services.json",
		"--nextrecoverkey-id", e.recover2KeyID, "--nextupdatekey-id",
		e.update3KeyID, "--signingkey-id", e.recoverKeyID)

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
		"--did-uri", e.createdDID.ID, "--kms-store-endpoint", e.keyStoreURL,
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem", "--sidetree-write-token", "ADMIN_TOKEN",
		"--signingkey-id", e.recover2KeyID)

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func (e *Steps) createDID() error {
	var args []string

	args = append(args, "did", "create", "--did-anchor-origin", "https://orb.domain1.com",
		"--kms-store-endpoint", e.keyStoreURL,
		"--sidetree-url", "https://localhost:48326/sidetree/v1/operations", "--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem",
		"--publickey-file", "fixtures/did-keys/create/publickeys.json",
		"--sidetree-write-token", "ADMIN_TOKEN", "--service-file", "fixtures/did-services/create/services.json",
		"--recoverykey-id", e.recoverKeyID, "--updatekey-id", e.updateKeyID)

	value, err := execCMD(args...)
	if err != nil {
		return err
	}

	e.cliValue = value

	e.state.setResponse(value)

	return nil
}

func (e *Steps) execute(argsStr string) error {
	if err := e.state.resolveVarsInExpression(&argsStr); err != nil {
		return err
	}

	value, err := execCMD(parseArgs(argsStr)...)
	if err != nil {
		return err
	}

	logger.Infof("Response from CLI: %s", value)

	e.state.setResponse(value)

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

func sendRequest(httpClient *http.Client, req []byte, headers map[string]string, method,
	endpointURL string) ([]byte, error) {
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	}

	for k, v := range headers {
		httpReq.Header.Add(k, v)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func closeResponseBody(respBody io.Closer) {
	if err := respBody.Close(); err != nil {
		logger.Errorf("Failed to close response body: %v", err)
	}
}

// SendHTTPRequest send http request.
func sendHTTPRequest(httpClient *http.Client, request interface{}, headers map[string]string, method,
	endpointURL string, response interface{}) error {
	reqBytes, err := json.Marshal(request)
	if err != nil {
		return err
	}

	responseBytes, err := sendRequest(httpClient, reqBytes, headers, method, endpointURL)
	if err != nil {
		return err
	}

	return json.Unmarshal(responseBytes, response)
}

func parseArgs(argsStr string) []string {
	var args []string

	var current string

	startStringIndex := -1

	for i := 0; i < len(argsStr); i++ {
		c := argsStr[i : i+1]

		switch {
		case c == "\"":
			if startStringIndex == -1 {
				startStringIndex = i
			} else {
				current = argsStr[startStringIndex+1 : i]
				startStringIndex = -1
			}
		case c == " " && startStringIndex == -1:
			args = append(args, current)
			current = ""
		default:
			current += argsStr[i : i+1]
		}
	}

	if current != "" {
		args = append(args, current)
	}

	return args
}
