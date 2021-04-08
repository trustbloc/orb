/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"

	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/test/bdd/restclient"
)

var logger = logrus.New()

const (
	didDocNamespace = "did:orb"

	initialStateSeparator = ":"

	origin = "origin.com"

	sha2_256 = 18

	anchorTimeDelta = 300
)

const addPublicKeysTemplate = `[
	{
      "id": "%s",
      "purposes": ["authentication"],
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256K",
        "x": "PUymIqdtF_qxaAqPABSw-C-owT1KYYQbsMKFM-L9fJA",
        "y": "nM84jDHCMOTGTh_ZdHq4dBBdo4Z5PkEOW9jA8z8IsGc"
      }
    }
  ]`

const removePublicKeysTemplate = `["%s"]`

const addServicesTemplate = `[
    {
      "id": "%s",
      "type": "SecureDataStore",
      "serviceEndpoint": "http://hub.my-personal-server.com"
    }
  ]`

const removeServicesTemplate = `["%s"]`

const docTemplate = `{
  "publicKey": [
   {
     "id": "%s",
     "type": "JsonWebKey2020",
     "purposes": ["authentication"],
     "publicKeyJwk": %s
   },
   {
     "id": "auth",
     "type": "Ed25519VerificationKey2018",
     "purposes": ["assertionMethod"],
     "publicKeyJwk": %s
   }
  ],
  "service": [
	{
	   "id": "didcomm",
	   "type": "did-communication",
	   "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
	   "recipientKeys": ["%s"],
	   "routingKeys": ["%s"],
	   "priority": 0
	}
  ]
}`

var emptyJson = []byte("{}")

// DIDOrbSteps
type DIDOrbSteps struct {
	namespace          string
	createRequest      *model.CreateRequest
	recoveryKey        *ecdsa.PrivateKey
	updateKey          *ecdsa.PrivateKey
	resp               *restclient.HttpRespone
	bddContext         *BDDContext
	alias              string
	uniqueSuffix       string
	canonicalID        string
	resolutionEndpoint string
	operationEndpoint  string
}

// NewDIDSideSteps
func NewDIDSideSteps(context *BDDContext, namespace string) *DIDOrbSteps {
	return &DIDOrbSteps{bddContext: context, namespace: namespace}
}

func (d *DIDOrbSteps) discoverEndpoints() error {
	resp, err := restclient.SendResolveRequest("https://localhost:48326/.well-known/did-orb")
	if err != nil {
		return err
	}

	var w restapi.WellKnownResponse
	if err := json.Unmarshal(resp.Payload, &w); err != nil {
		return err
	}

	resp, err = restclient.SendResolveRequest(
		fmt.Sprintf("https://localhost:48326/.well-known/webfinger?resource=%s",
			url.PathEscape(w.ResolutionEndpoint)))
	if err != nil {
		return err
	}

	var webFingerResponse restapi.WebFingerResponse
	if err := json.Unmarshal(resp.Payload, &webFingerResponse); err != nil {
		return err
	}

	d.resolutionEndpoint = strings.ReplaceAll(webFingerResponse.Links[0].Href, "orb.domain1.com", "localhost:48326")

	resp, err = restclient.SendResolveRequest(
		fmt.Sprintf("https://localhost:48326/.well-known/webfinger?resource=%s",
			url.PathEscape(w.OperationEndpoint)))
	if err != nil {
		return err
	}

	if err := json.Unmarshal(resp.Payload, &webFingerResponse); err != nil {
		return err
	}

	d.operationEndpoint = strings.ReplaceAll(webFingerResponse.Links[0].Href, "orb.domain1.com", "localhost:48326")

	return nil
}

func (d *DIDOrbSteps) createDIDDocument(url string) error {
	var err error

	logger.Info("create did document")

	opaqueDoc, err := d.getOpaqueDocument("createKey")
	if err != nil {
		return err
	}

	reqBytes, err := d.getCreateRequest(opaqueDoc, nil)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(url, reqBytes)
	if err == nil {
		var req model.CreateRequest
		e := json.Unmarshal(reqBytes, &req)
		if e != nil {
			return e
		}

		d.createRequest = &req
	}

	return err
}

func (d *DIDOrbSteps) updateDIDDocument(url string, patches []patch.Patch) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document: %s", uniqueSuffix)

	req, err := d.getUpdateRequest(uniqueSuffix, patches)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(url, req)
	return err
}

func (d *DIDOrbSteps) deactivateDIDDocument(url string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("deactivate did document: %s", uniqueSuffix)

	req, err := d.getDeactivateRequest(uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(url, req)
	return err
}

func (d *DIDOrbSteps) recoverDIDDocument(url string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("recover did document")

	opaqueDoc, err := d.getOpaqueDocument("recoveryKey")
	if err != nil {
		return err
	}

	req, err := d.getRecoverRequest(opaqueDoc, nil, uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendRequest(url, req)
	return err
}

func (d *DIDOrbSteps) addPublicKeyToDIDDocument(url, keyID string) error {
	p, err := getAddPublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(url, []patch.Patch{p})
}

func (d *DIDOrbSteps) removePublicKeyFromDIDDocument(url, keyID string) error {
	p, err := getRemovePublicKeysPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(url, []patch.Patch{p})
}

func (d *DIDOrbSteps) addServiceEndpointToDIDDocument(url, keyID string) error {
	p, err := getAddServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(url, []patch.Patch{p})
}

func (d *DIDOrbSteps) removeServiceEndpointsFromDIDDocument(url, keyID string) error {
	p, err := getRemoveServiceEndpointsPatch(keyID)
	if err != nil {
		return err
	}

	return d.updateDIDDocument(url, []patch.Patch{p})
}

func (d *DIDOrbSteps) checkErrorResp(errorMsg string) error {
	if !strings.Contains(d.resp.ErrorMsg, errorMsg) {
		return fmt.Errorf("error resp %s doesn't contain %s", d.resp.ErrorMsg, errorMsg)
	}
	return nil
}

func (d *DIDOrbSteps) checkSuccessRespContains(msg string) error {
	return d.checkSuccessResp(msg, true)
}

func (d *DIDOrbSteps) checkSuccessRespDoesntContain(msg string) error {
	return d.checkSuccessResp(msg, false)
}

func (d *DIDOrbSteps) checkSuccessResp(msg string, contains bool) error {
	if d.resp.ErrorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	if msg == "#did" || msg == "#aliasdid" || msg == "#emptydoc" || msg == "#canonicalId" {
		ns := d.namespace
		if msg == "#aliasdid" {
			ns = d.alias
		}

		did, err := d.getDIDWithNamespace(ns)
		if err != nil {
			return err
		}

		msg = strings.Replace(msg, "#did", did, -1)
		msg = strings.Replace(msg, "#canonicalId", d.canonicalID, -1)
		msg = strings.Replace(msg, "#aliasdid", did, -1)

		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		didDoc := document.DidDocumentFromJSONLDObject(result.Document)

		// perform basic checks on document
		if didDoc.ID() == "" || didDoc.Context()[0] != "https://www.w3.org/ns/did/v1" ||
			(len(didDoc.PublicKeys()) > 0 && !strings.Contains(didDoc.PublicKeys()[0].Controller(), didDoc.ID())) {
			return fmt.Errorf("response is not a valid did document")
		}

		if msg == "#emptydoc" {
			if len(didDoc) > 2 { // has id and context
				return fmt.Errorf("response is not an empty document")
			}

			logger.Info("response contains empty did document")

			return nil
		}

		logger.Infof("response is a valid did document")
	}

	action := " "
	if !contains {
		action = " NOT"
	}

	if contains && !strings.Contains(string(d.resp.Payload), msg) {
		return fmt.Errorf("success resp doesn't contain %s", msg)
	}

	if !contains && strings.Contains(string(d.resp.Payload), msg) {
		return fmt.Errorf("success resp should NOT contain %s", msg)
	}

	logger.Infof("passed check that success response MUST%s contain %s", action, msg)

	return nil
}

func (d *DIDOrbSteps) resolveDIDDocumentWithID(url, did string) error {
	var err error
	d.resp, err = restclient.SendResolveRequest(d.resolutionEndpoint + "/" + did)

	if err == nil && d.resp.Payload != nil {
		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		err = prettyPrint(&result)
		if err != nil {
			return err
		}

		d.canonicalID = result.DocumentMetadata["canonicalId"].(string)
	}

	return err
}

func (d *DIDOrbSteps) resolveDIDDocument(url string) error {
	did, err := d.getDID()
	if err != nil {
		return err
	}

	logger.Infof("resolving did document with did: %s", did)
	return d.resolveDIDDocumentWithID(url, did)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithCanonicalID(url string) error {
	logger.Infof("resolving did document with canonical id: %s", d.canonicalID)

	return d.resolveDIDDocumentWithID(url, d.canonicalID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithAlias(url, alias string) error {
	did, err := d.getDIDWithNamespace(alias)
	if err != nil {
		return err
	}

	d.alias = alias

	d.resp, err = restclient.SendResolveRequest(url + "/" + did)
	return err
}

func (d *DIDOrbSteps) resolveDIDDocumentWithInitialValue(url string) error {
	did, err := d.getDID()
	if err != nil {
		return err
	}

	initialState, err := d.getInitialState()
	if err != nil {
		return err
	}

	d.resp, err = restclient.SendResolveRequest(url + "/" + did + initialStateSeparator + initialState)
	return err
}

func (d *DIDOrbSteps) getInitialState() (string, error) {
	createReq := &model.CreateRequest{
		Delta:      d.createRequest.Delta,
		SuffixData: d.createRequest.SuffixData,
	}

	bytes, err := canonicalizer.MarshalCanonical(createReq)
	if err != nil {
		return "", err
	}

	return encoder.EncodeToString(bytes), nil
}

func (d *DIDOrbSteps) getCreateRequest(doc []byte, patches []patch.Patch) ([]byte, error) {
	recoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	d.recoveryKey = recoveryKey

	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	d.updateKey = updateKey

	return client.NewCreateRequest(&client.CreateRequestInfo{
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		AnchorOrigin:       origin,
	})
}

func (d *DIDOrbSteps) getRecoverRequest(doc []byte, patches []patch.Patch, uniqueSuffix string) ([]byte, error) {
	recoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	revealValue, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	recoverRequest, err := client.NewRecoverRequest(&client.RecoverRequestInfo{
		DidSuffix:          uniqueSuffix,
		RevealValue:        revealValue,
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(d.recoveryKey, "ES256", ""), // sign with old signer
		AnchorFrom:         now,
		AnchorUntil:        now + anchorTimeDelta,
		AnchorOrigin:       origin,
	})

	if err != nil {
		return nil, err
	}

	// update recovery and update key for subsequent requests
	d.recoveryKey = recoveryKey
	d.updateKey = updateKey

	return recoverRequest, nil
}

func (d *DIDOrbSteps) getDID() (string, error) {
	return d.getDIDWithNamespace(didDocNamespace)
}

func (d *DIDOrbSteps) getDIDWithNamespace(namespace string) (string, error) {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return "", err
	}

	didID := namespace + docutil.NamespaceDelimiter + uniqueSuffix
	return didID, nil
}

func (d *DIDOrbSteps) getUniqueSuffix() (string, error) {
	return hashing.CalculateModelMultihash(d.createRequest.SuffixData, sha2_256)
}

func (d *DIDOrbSteps) getDeactivateRequest(did string) ([]byte, error) {
	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&d.recoveryKey.PublicKey)
	if err != nil {
		return nil, err
	}

	revealValue, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   did,
		RevealValue: revealValue,
		RecoveryKey: recoveryPubKey,
		Signer:      ecsigner.New(d.recoveryKey, "ES256", ""),
		AnchorFrom:  time.Now().Unix(),
	})
}

func (d *DIDOrbSteps) getUpdateRequest(did string, patches []patch.Patch) ([]byte, error) {
	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, err
	}

	// update key and signer passed in are generated during previous operations
	updatePubKey, err := pubkey.GetPublicKeyJWK(&d.updateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	revealValue, err := commitment.GetRevealValue(updatePubKey, sha2_256)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	req, err := client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        did,
		RevealValue:      revealValue,
		UpdateCommitment: updateCommitment,
		UpdateKey:        updatePubKey,
		Patches:          patches,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(d.updateKey, "ES256", ""),
		AnchorFrom:       now,
		AnchorUntil:      now + anchorTimeDelta,
	})

	if err != nil {
		return nil, err
	}

	// update update key for subsequent update requests
	d.updateKey = updateKey

	return req, nil
}

func generateKeyAndCommitment() (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}

	pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return nil, "", err
	}

	c, err := commitment.GetCommitment(pubKey, sha2_256)
	if err != nil {
		return nil, "", err
	}

	return key, c, nil
}

func getJSONPatch(path, value string) (patch.Patch, error) {
	patches := fmt.Sprintf(`[{"op": "replace", "path":  "%s", "value": "%s"}]`, path, value)
	logger.Infof("creating JSON patch: %s", patches)
	return patch.NewJSONPatch(patches)
}

func getAddPublicKeysPatch(keyID string) (patch.Patch, error) {
	addPubKeys := fmt.Sprintf(addPublicKeysTemplate, keyID)
	logger.Infof("creating add public keys patch: %s", addPubKeys)
	return patch.NewAddPublicKeysPatch(addPubKeys)
}

func getRemovePublicKeysPatch(keyID string) (patch.Patch, error) {
	removePubKeys := fmt.Sprintf(removePublicKeysTemplate, keyID)
	logger.Infof("creating remove public keys patch: %s", removePubKeys)
	return patch.NewRemovePublicKeysPatch(removePubKeys)
}

func getAddServiceEndpointsPatch(svcID string) (patch.Patch, error) {
	addServices := fmt.Sprintf(addServicesTemplate, svcID)
	logger.Infof("creating add service endpoints patch: %s", addServices)
	return patch.NewAddServiceEndpointsPatch(addServices)
}

func getRemoveServiceEndpointsPatch(keyID string) (patch.Patch, error) {
	removeServices := fmt.Sprintf(removeServicesTemplate, keyID)
	logger.Infof("creating remove service endpoints patch: %s", removeServices)
	return patch.NewRemoveServiceEndpointsPatch(removeServices)
}

func (d *DIDOrbSteps) getOpaqueDocument(keyID string) ([]byte, error) {
	// create general + auth JWS verification key
	jwsPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwsPubKey, err := getPubKey(&jwsPrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	// create general + assertion ed25519 verification key
	ed25519PulicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	ed25519PubKey, err := getPubKey(ed25519PulicKey)
	if err != nil {
		return nil, err
	}

	recipientKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	routingKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	data := fmt.Sprintf(
		docTemplate,
		keyID, jwsPubKey, ed25519PubKey, base58.Encode(recipientKey), base58.Encode(routingKey))

	doc, err := document.FromBytes([]byte(data))
	if err != nil {
		return nil, err
	}

	return doc.Bytes()
}

func getPubKey(pubKey interface{}) (string, error) {
	publicKey, err := pubkey.GetPublicKeyJWK(pubKey)
	if err != nil {
		return "", err
	}

	opsPubKeyBytes, err := json.Marshal(publicKey)
	if err != nil {
		return "", err
	}

	return string(opsPubKeyBytes), nil
}

func prettyPrint(result *document.ResolutionResult) error {
	b, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		return err
	}

	fmt.Println(string(b))

	return nil
}

// RegisterSteps registers orb steps
func (d *DIDOrbSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client discover orb endpoints$`, d.discoverEndpoints)
	s.Step(`^check error response contains "([^"]*)"$`, d.checkErrorResp)
	s.Step(`^client sends request to "([^"]*)" to create DID document$`, d.createDIDDocument)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessRespContains)
	s.Step(`^check success response does NOT contain "([^"]*)"$`, d.checkSuccessRespDoesntContain)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document$`, d.resolveDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with canonical id$`, d.resolveDIDDocumentWithCanonicalID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with alias "([^"]*)"$`, d.resolveDIDDocumentWithAlias)
	s.Step(`^client sends request to "([^"]*)" to add public key with ID "([^"]*)" to DID document$`, d.addPublicKeyToDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to remove public key with ID "([^"]*)" from DID document$`, d.removePublicKeyFromDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to add service endpoint with ID "([^"]*)" to DID document$`, d.addServiceEndpointToDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to remove service endpoint with ID "([^"]*)" from DID document$`, d.removeServiceEndpointsFromDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to deactivate DID document$`, d.deactivateDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to recover DID document$`, d.recoverDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with initial state$`, d.resolveDIDDocumentWithInitialValue)
}
