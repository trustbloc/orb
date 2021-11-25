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
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/mr-tron/base58"
	"github.com/sirupsen/logrus"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/encoder"
	"github.com/trustbloc/sidetree-core-go/pkg/hashing"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/model"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
	"github.com/trustbloc/orb/pkg/cas/ipfs"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/orbclient"
	"github.com/trustbloc/orb/pkg/orbclient/resolveverifier"
)

var logger = logrus.New()

const (
	didDocNamespace = "did:orb"

	initialStateSeparator = ":"

	sha2_256 = 18

	anchorTimeDelta = 300

	testCID = "bafkreie4a6z6hosibbfz2dd7vhsukojw3gwmldh5jvy5uh3mjfrubiq5hi"
)

var localURLs = map[string]string{
	"https://orb.domain1.com":  "https://localhost:48326",
	"https://orb2.domain1.com": "https://localhost:48526",
	"https://orb.domain2.com":  "https://localhost:48426",
	"https://orb.domain3.com":  "https://localhost:48626",
	"https://orb.domain4.com":  "https://localhost:48726",
}

var anchorOriginURLs = map[string]string{
	"https://localhost:48326/sidetree/v1/operations": "https://orb.domain1.com",
	"https://localhost:48526/sidetree/v1/operations": "ipns://k51qzi5uqu5dgkmm1afrkmex5mzpu5r774jstpxjmro6mdsaullur27nfxle1q",
	"https://localhost:48426/sidetree/v1/operations": "https://orb.domain1.com",
	"https://localhost:48626/sidetree/v1/operations": "https://orb.domain3.com",
	"https://localhost:48726/sidetree/v1/operations": "https://orb.domain1.com",
}

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

// DIDOrbSteps
type DIDOrbSteps struct {
	state *state

	namespace          string
	createRequest      *model.CreateRequest
	recoveryKeys       []*ecdsa.PrivateKey
	updateKeys         []*ecdsa.PrivateKey
	resp               *httpResponse
	resolutionResult   *document.ResolutionResult
	bddContext         *BDDContext
	interimDID         string
	prevCanonicalDID   string
	canonicalDID       string
	prevEquivalentDID  []string
	equivalentDID      []string
	retryDID           string
	resolutionEndpoint string
	operationEndpoint  string
	sidetreeURL        string
	dids               []string
	httpClient         *httpClient
	didPrintEnabled    bool
}

// NewDIDSideSteps
func NewDIDSideSteps(context *BDDContext, state *state, namespace string) *DIDOrbSteps {
	return &DIDOrbSteps{
		bddContext:      context,
		state:           state,
		namespace:       namespace,
		httpClient:      newHTTPClient(state, context),
		didPrintEnabled: true,
	}
}

func (d *DIDOrbSteps) discoverEndpoints() error {
	resp, err := d.httpClient.Get("https://localhost:48326/.well-known/did-orb")
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	var w restapi.WellKnownResponse
	if err := json.Unmarshal(resp.Payload, &w); err != nil {
		return err
	}

	resp, err = d.httpClient.Get(
		fmt.Sprintf("https://localhost:48326/.well-known/webfinger?resource=%s",
			url.PathEscape(w.ResolutionEndpoint)))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d: %s", resp.StatusCode, resp.ErrorMsg)
	}

	var webFingerResponse restapi.JRD
	if err := json.Unmarshal(resp.Payload, &webFingerResponse); err != nil {
		return err
	}

	d.resolutionEndpoint = strings.ReplaceAll(webFingerResponse.Links[0].Href, "orb.domain1.com", "localhost:48326")

	resp, err = d.httpClient.Get(
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

type provider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *provider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func (d *DIDOrbSteps) clientRequestsAnchorOrigin(url string) error {
	logger.Info("requesting anchor origin (client)")

	if os.Getenv("CAS_TYPE") != "ipfs" {
		logger.Info("ignoring 'request anchor origin' test case since cas type is NOT set to 'ifps'")
		return nil
	}

	cid, suffix, err := extractCIDAndSuffix(d.canonicalDID)
	if err != nil {
		return err
	}

	contextStore, err := ldstore.NewContextStore(mem.NewProvider())
	if err != nil {
		return fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(mem.NewProvider())
	if err != nil {
		return fmt.Errorf("create remote provider store: %w", err)
	}

	p := &provider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	docLoader, err := ld.NewDocumentLoader(p, ld.WithExtraContexts(ldcontext.MustGetAll()...))

	casClient := ipfs.New(url, 20*time.Second, 0, &mocks.MetricsProvider{})

	orbClient, err := orbclient.New(didDocNamespace, casClient,
		orbclient.WithJSONLDDocumentLoader(docLoader),
		orbclient.WithDisableProofCheck(true))
	if err != nil {
		return err
	}

	anchorOriginObj, err := orbClient.GetAnchorOrigin(cid, suffix)
	if err != nil {
		return err
	}

	anchorOrigin, ok := anchorOriginObj.(string)
	if !ok {
		return fmt.Errorf("unexpected interface '%T' for anchor origin object", anchorOriginObj)
	}

	logger.Infof("got anchor origin: %s", anchorOrigin)

	expectedOrigin := "https://orb.domain1.com"
	if anchorOrigin != expectedOrigin {
		return fmt.Errorf("anchor origin: expected %s, got %s", expectedOrigin, anchorOrigin)
	}

	return err
}

func (d *DIDOrbSteps) clientVerifiesResolvedDocument() error {
	logger.Info("verify resolved document (client)")

	verifier, err := resolveverifier.New("did:orb")
	if err != nil {
		return err
	}

	return verifier.Verify(d.resolutionResult)
}

func extractCIDAndSuffix(canonicalID string) (string, string, error) {
	parts := strings.Split(canonicalID, ":")

	if len(parts) != 4 {
		return "", "", fmt.Errorf("expected 4 got %d parts for canonical ID", len(parts))
	}

	return parts[2], parts[3], nil
}

func (d *DIDOrbSteps) createDIDDocumentSaveIDToVar(url, varName string) error {
	if err := d.createDIDDocument(url); err != nil {
		return err
	}

	d.state.setVar(varName, d.interimDID)

	return nil
}

func (d *DIDOrbSteps) resetKeysToLastSuccessful(url string) error {
	err := d.resolveDIDDocumentWithID(url, d.canonicalDID)
	if err != nil {
		return err
	}

	var result document.ResolutionResult
	err = json.Unmarshal(d.resp.Payload, &result)
	if err != nil {
		return err
	}

	metadataObj, ok := result.DocumentMetadata["method"]
	if !ok {
		return fmt.Errorf("missing method")
	}

	metadataMap, ok := metadataObj.(map[string]interface{})
	if !ok {
		return fmt.Errorf("method is wrong type")
	}

	updateCommitment := metadataMap[document.UpdateCommitmentProperty].(string)
	recoveryCommitment := metadataMap[document.RecoveryCommitmentProperty].(string)

	d.updateKeys, err = removeKeysAfterCommitment(d.updateKeys, updateCommitment)
	if err != nil {
		return err
	}

	d.recoveryKeys, err = removeKeysAfterCommitment(d.recoveryKeys, recoveryCommitment)
	if err != nil {
		return err
	}

	return nil
}

func removeKeysAfterCommitment(keys []*ecdsa.PrivateKey, cmt string) ([]*ecdsa.PrivateKey, error) {
	for index, key := range keys {
		pubKey, err := pubkey.GetPublicKeyJWK(&key.PublicKey)
		if err != nil {
			return nil, err
		}

		c, err := commitment.GetCommitment(pubKey, sha2_256)
		if err != nil {
			return nil, err
		}

		if c == cmt {
			logger.Infof("found key index '%d' of %d keys that corresponds to last successful commitment '%s'", index, len(keys), cmt)
			return keys[:index+1], nil
		}
	}

	return keys, nil
}

func (d *DIDOrbSteps) createDIDDocument(url string) error {
	logger.Info("create did document")

	d.recoveryKeys = nil
	d.updateKeys = nil

	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	opaqueDoc, err := getOpaqueDocument("createKey")
	if err != nil {
		return err
	}

	recoveryKey, updateKey, reqBytes, err := getCreateRequest(d.sidetreeURL, opaqueDoc, nil)
	if err != nil {
		return err
	}

	d.recoveryKeys = append(d.recoveryKeys, recoveryKey)
	d.updateKeys = append(d.updateKeys, updateKey)

	d.resp, err = d.httpClient.Post(d.sidetreeURL, reqBytes, "application/json")
	if err == nil && d.resp.StatusCode == http.StatusOK {
		var req model.CreateRequest
		e := json.Unmarshal(reqBytes, &req)
		if e != nil {
			return e
		}

		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		d.prettyPrint(&result)

		d.createRequest = &req
		d.interimDID = result.Document["id"].(string)
		d.bddContext.createdDID = result.Document["id"].(string)
		d.equivalentDID = document.StringArray(result.DocumentMetadata["equivalentId"])
	}

	return err
}

func (d *DIDOrbSteps) setSidetreeURL(url string) error {
	localURL, err := getLocalURL(url, "/sidetree/v1/")
	if err != nil {
		return err
	}

	d.sidetreeURL = localURL

	return nil
}

func getLocalURL(url, separator string) (string, error) {
	parts := strings.Split(url, separator)

	if len(parts) != 2 {
		return "", fmt.Errorf("wrong format of URL: %s", url)
	}

	externalURL := parts[0]

	if strings.Contains(externalURL, "localhost") {
		// already internal url - nothing to do
		return url, nil
	}

	localURL, ok := localURLs[externalURL]
	if !ok {
		return "", fmt.Errorf("server URL not configured for: %s", url)
	}

	return strings.ReplaceAll(url, externalURL, localURL), nil
}

func (d *DIDOrbSteps) updateDIDDocument(url string, patches []patch.Patch) error {
	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("update did document: %s", uniqueSuffix)

	req, updateKey, err := d.getUpdateRequest(uniqueSuffix, patches)
	if err != nil {
		return err
	}

	d.resp, err = d.httpClient.Post(d.sidetreeURL, req, "application/json")
	if err == nil && d.resp.StatusCode == http.StatusOK {
		// update update key for subsequent update requests
		d.updateKeys = append(d.updateKeys, updateKey)
	}

	return err
}

func (d *DIDOrbSteps) deactivateDIDDocument(url string) error {
	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("deactivate did document: %s", uniqueSuffix)

	req, err := d.getDeactivateRequest(uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = d.httpClient.Post(d.sidetreeURL, req, "application/json")
	return err
}

func (d *DIDOrbSteps) recoverDIDDocument(url string) error {
	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	logger.Infof("recover did document")

	opaqueDoc, err := getOpaqueDocument("recoveryKey")
	if err != nil {
		return err
	}

	req, recoveryKey, updateKey, err := d.getRecoverRequest(opaqueDoc, nil, uniqueSuffix)
	if err != nil {
		return err
	}

	d.resp, err = d.httpClient.Post(d.sidetreeURL, req, "application/json")
	if err == nil && d.resp.StatusCode == http.StatusOK {
		// update recovery and update key for subsequent requests
		d.recoveryKeys = append(d.recoveryKeys, recoveryKey)
		d.updateKeys = append(d.updateKeys, updateKey)
	}

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
		return fmt.Errorf(`error resp "%s" doesn't contain "%s" status: %d`, d.resp.ErrorMsg, errorMsg, d.resp.StatusCode)
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
	var err error

	const maxRetries = 5

	for i := 1; i <= maxRetries; i++ {
		err = d.checkSuccessRespHelper(msg, contains)
		if err == nil {
			return nil
		}

		if !strings.Contains(d.sidetreeURL, "identifiers") {
			// retries are for resolution only
			return err
		}

		time.Sleep(2 * time.Second)
		logger.Infof("retrying check success response - attempt %d", i)

		resolveErr := d.resolveDIDDocumentWithID(d.sidetreeURL, d.retryDID)
		if resolveErr != nil {
			return resolveErr
		}
	}

	return err
}

func (d *DIDOrbSteps) checkSuccessRespHelper(msg string, contains bool) error {
	if d.resp.ErrorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	if msg == "#interimDID" || msg == "#canonicalDID" || msg == "#emptydoc" {

		msg = strings.Replace(msg, "#canonicalDID", d.canonicalDID, -1)
		msg = strings.Replace(msg, "#interimDID", d.interimDID, -1)

		var result document.ResolutionResult
		err := json.Unmarshal(d.resp.Payload, &result)
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

func (d *DIDOrbSteps) checkResponseIsSuccess() error {
	if d.resp.ErrorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.ErrorMsg)
	}

	return nil
}

func (d *DIDOrbSteps) getPayloadForRequest(url string) ([]byte, error) {
	logger.Infof("sending request: %s", url)

	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status[%d], msg: %s", resp.StatusCode, resp.ErrorMsg)
	}

	return resp.Payload, nil
}

func (d *DIDOrbSteps) resolveDIDDocumentWithID(url, did string) error {
	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	d.resp, err = d.httpClient.Get(d.sidetreeURL + "/" + did)

	logger.Infof("sending request: %s", d.sidetreeURL+"/"+did)

	if err == nil && d.resp.Payload != nil {
		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		d.resolutionResult = &result

		err = d.prettyPrint(&result)
		if err != nil {
			return err
		}

		canonicalIDEntry, ok := result.DocumentMetadata["canonicalId"]
		if ok {
			d.prevCanonicalDID = d.canonicalDID
			d.canonicalDID = canonicalIDEntry.(string)
		}

		equivalentIDEntry, ok := result.DocumentMetadata["equivalentId"]
		if ok {
			d.prevEquivalentDID = d.equivalentDID
			d.equivalentDID = document.StringArray(equivalentIDEntry)
		}
	}

	return err
}

func (d *DIDOrbSteps) resolveDIDDocumentWithInterimDID(url string) error {
	logger.Infof("resolving did document with did: %s", d.interimDID)

	d.retryDID = d.interimDID

	return d.resolveDIDDocumentWithID(url, d.interimDID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithCanonicalDID(url string) error {
	logger.Infof("resolving did document with canonical did: %s", d.canonicalDID)

	d.retryDID = d.canonicalDID

	return d.resolveDIDDocumentWithID(url, d.canonicalDID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithHint(url, hint string) error {
	cannonicalDIDParts := strings.SplitAfter(d.canonicalDID, d.namespace)

	didWithHint := cannonicalDIDParts[0] + ":" + hint + cannonicalDIDParts[1]

	logger.Infof("resolving did with hint: %s", didWithHint)

	d.retryDID = didWithHint

	return d.resolveDIDDocumentWithID(url, didWithHint)
}

func (d *DIDOrbSteps) resolveInterimDIDDocumentWithHint(url, hint string) error {
	interimDIDParts := strings.SplitAfter(d.interimDID, d.namespace)

	interimDidWithHint := interimDIDParts[0] + ":" + hint + interimDIDParts[1]

	logger.Infof("resolving interim did with hint: %s", interimDidWithHint)

	d.retryDID = interimDidWithHint

	return d.resolveDIDDocumentWithID(url, interimDidWithHint)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithPreviousCanonicalDID(url string) error {
	logger.Infof("resolving did document with previous canonical did: %s", d.prevCanonicalDID)

	d.retryDID = d.prevCanonicalDID

	return d.resolveDIDDocumentWithID(url, d.prevCanonicalDID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithInvalidCIDInDID(url string) error {
	uniqueSuffix, err := d.getUniqueSuffix()
	if err != nil {
		return err
	}

	didWithInvalidCID := d.namespace + ":" + testCID + ":" + uniqueSuffix

	logger.Infof("resolving did document with previous invalid CID in did: %s", didWithInvalidCID)

	d.retryDID = didWithInvalidCID

	return d.resolveDIDDocumentWithID(url, didWithInvalidCID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithEquivalentDID(url string) error {
	// interim DID contains one equivalent ID
	equivalentDID := d.equivalentDID[len(d.equivalentDID)-1]

	// permanent DID has 2 or more equivalent IDs:
	// first one is canonical ID (Sidetree spec),
	// second one is with originator hint,
	// third one is with shared domain hint (if configured)
	if len(d.equivalentDID) > 1 {
		equivalentDID = d.equivalentDID[1]
	}

	logger.Infof("resolving did document with equivalent did: %s", equivalentDID)

	d.retryDID = equivalentDID

	// last equivalent ID is an ID with hints (canonical ID is always the first for published docs)
	return d.resolveDIDDocumentWithID(url, equivalentDID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithPreviousEquivalentDID(url string) error {
	prevEquivalentDID := d.prevEquivalentDID[len(d.prevEquivalentDID)-1]

	if len(d.prevEquivalentDID) > 1 {
		prevEquivalentDID = d.prevEquivalentDID[1]
	}

	logger.Infof("resolving did document with previous equivalent did: %s", prevEquivalentDID)

	d.retryDID = prevEquivalentDID

	// last equivalent ID is an ID with hints (canonical ID is always the first for published docs)
	return d.resolveDIDDocumentWithID(url, prevEquivalentDID)
}

func (d *DIDOrbSteps) resolveDIDDocumentWithInitialValue(url string) error {
	err := d.setSidetreeURL(url)
	if err != nil {
		return err
	}

	initialState, err := d.getInitialState()
	if err != nil {
		return err
	}

	interimDIDWithInitialValue := d.interimDID + initialStateSeparator + initialState

	logger.Infof("sending request with initial value: %s", d.sidetreeURL+"/"+interimDIDWithInitialValue)

	d.resp, err = d.httpClient.Get(d.sidetreeURL + "/" + interimDIDWithInitialValue)
	if err == nil && d.resp.Payload != nil {
		var result document.ResolutionResult
		err = json.Unmarshal(d.resp.Payload, &result)
		if err != nil {
			return err
		}

		err = d.prettyPrint(&result)
		if err != nil {
			return err
		}
	}

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

func getCreateRequest(url string, doc []byte, patches []patch.Patch) (*ecdsa.PrivateKey, *ecdsa.PrivateKey, []byte, error) {
	recoveryKey, recoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, nil, err
	}

	updateKey, updateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, nil, err
	}

	origin, ok := anchorOriginURLs[url]
	if !ok {
		return nil, nil, nil, fmt.Errorf("anchor origin not configured for %s", url)
	}

	reqBytes, err := client.NewCreateRequest(&client.CreateRequestInfo{
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
		AnchorOrigin:       origin,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return recoveryKey, updateKey, reqBytes, nil
}

func (d *DIDOrbSteps) getRecoverRequest(doc []byte, patches []patch.Patch, uniqueSuffix string) ([]byte, *ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	currentRecoveryKey := d.getLatestRecoveryKey()

	nextRecoveryKey, nextRecoveryCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, nil, err
	}

	nextUpdateKey, nextUpdateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, nil, err
	}

	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&currentRecoveryKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	revealValue, err := commitment.GetRevealValue(recoveryPubKey, sha2_256)
	if err != nil {
		return nil, nil, nil, err
	}

	now := time.Now().Unix()

	origin, ok := anchorOriginURLs[d.sidetreeURL]
	if !ok {
		return nil, nil, nil, fmt.Errorf("anchor origin not configured for %s", d.sidetreeURL)
	}

	recoverRequest, err := client.NewRecoverRequest(&client.RecoverRequestInfo{
		DidSuffix:          uniqueSuffix,
		RevealValue:        revealValue,
		OpaqueDocument:     string(doc),
		Patches:            patches,
		RecoveryKey:        recoveryPubKey,
		RecoveryCommitment: nextRecoveryCommitment,
		UpdateCommitment:   nextUpdateCommitment,
		MultihashCode:      sha2_256,
		Signer:             ecsigner.New(currentRecoveryKey, "ES256", ""), // sign with old signer
		AnchorFrom:         now,
		AnchorUntil:        now + anchorTimeDelta,
		AnchorOrigin:       origin,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return recoverRequest, nextRecoveryKey, nextUpdateKey, nil
}

func (d *DIDOrbSteps) getUniqueSuffix() (string, error) {
	return hashing.CalculateModelMultihash(d.createRequest.SuffixData, sha2_256)
}

func (d *DIDOrbSteps) getDeactivateRequest(did string) ([]byte, error) {
	currentRecoveryKey := d.getLatestRecoveryKey()

	// recovery key and signer passed in are generated during previous operations
	recoveryPubKey, err := pubkey.GetPublicKeyJWK(&currentRecoveryKey.PublicKey)
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
		Signer:      ecsigner.New(currentRecoveryKey, "ES256", ""),
		AnchorFrom:  time.Now().Unix(),
	})
}

func (d *DIDOrbSteps) getLatestRecoveryKey() *ecdsa.PrivateKey {
	return d.recoveryKeys[len(d.recoveryKeys)-1]
}

func (d *DIDOrbSteps) getLatestUpdateKey() *ecdsa.PrivateKey {
	return d.updateKeys[len(d.updateKeys)-1]
}

func (d *DIDOrbSteps) getUpdateRequest(did string, patches []patch.Patch) ([]byte, *ecdsa.PrivateKey, error) {
	currentUpdateKey := d.getLatestUpdateKey()

	nextUpdateKey, nextUpdateCommitment, err := generateKeyAndCommitment()
	if err != nil {
		return nil, nil, err
	}

	// update key and signer passed in are generated during previous operations
	updatePubKey, err := pubkey.GetPublicKeyJWK(&currentUpdateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	revealValue, err := commitment.GetRevealValue(updatePubKey, sha2_256)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().Unix()

	req, err := client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        did,
		RevealValue:      revealValue,
		UpdateCommitment: nextUpdateCommitment,
		UpdateKey:        updatePubKey,
		Patches:          patches,
		MultihashCode:    sha2_256,
		Signer:           ecsigner.New(currentUpdateKey, "ES256", ""),
		AnchorFrom:       now,
		AnchorUntil:      now + anchorTimeDelta,
	})
	if err != nil {
		return nil, nil, err
	}

	return req, nextUpdateKey, nil
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

func getOpaqueDocument(keyID string) ([]byte, error) {
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

func (d *DIDOrbSteps) prettyPrint(result *document.ResolutionResult) error {
	if d.didPrintEnabled {

		b, err := json.MarshalIndent(result, "", " ")
		if err != nil {
			return err
		}

		fmt.Println(string(b))
	}

	return nil
}

func (d *DIDOrbSteps) createDIDDocuments(strURLs string, num int, concurrency int) error {
	logger.Infof("creating %d DID document(s) at %s using a concurrency of %d", num, strURLs, concurrency)

	urls := strings.Split(strURLs, ",")

	d.dids = nil

	p := NewWorkerPool(concurrency)

	p.Start()

	for i := 0; i < num; i++ {
		randomURL := urls[mrand.Intn(len(urls))]

		localURL, err := getLocalURL(randomURL, "/sidetree/v1/")
		if err != nil {
			return err
		}

		p.Submit(&createDIDRequest{
			url:        localURL,
			httpClient: d.httpClient,
		})
	}

	p.Stop()

	logger.Infof("got %d responses for %d requests", len(p.responses), num)

	if len(p.responses) != num {
		return fmt.Errorf("expecting %d responses but got %d", num, len(p.responses))
	}

	for _, resp := range p.responses {
		req := resp.Request.(*createDIDRequest)
		if resp.Err != nil {
			logger.Infof("got error from [%s]: %s", req.url, resp.Err)
			return resp.Err
		}

		did := resp.Resp.(string)
		logger.Infof("got DID from [%s]: %s", req.url, did)
		d.dids = append(d.dids, did)
	}

	return nil
}

func (d *DIDOrbSteps) verifyDIDDocuments(strURLs string) error {
	logger.Infof("Verifying the %d DID document(s) that were created", len(d.dids))

	urls := strings.Split(strURLs, ",")

	for i, did := range d.dids {
		randomURL := urls[mrand.Intn(len(urls))]

		localURL, err := getLocalURL(randomURL, "/sidetree/v1/")
		if err != nil {
			return err
		}

		if err := d.verifyDID(localURL, did); err != nil {
			return err
		}

		logger.Infof("... verified %d out of %d DIDs", i+1, len(d.dids))
	}

	return nil
}

func (d *DIDOrbSteps) verifyDID(url, did string) error {
	logger.Infof("verifying DID %s from %s", did, url)

	resp, err := d.httpClient.GetWithRetry(url+"/"+did, 25, http.StatusNotFound)
	if err != nil {
		return fmt.Errorf("failed to resolve DID[%s]: %w", did, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to resolve DID [%s] - Status code %d: %s", did, resp.StatusCode, resp.ErrorMsg)
	}

	var rr document.ResolutionResult
	err = json.Unmarshal(resp.Payload, &rr)
	if err != nil {
		return err
	}

	canonicalID, ok := rr.DocumentMetadata["canonicalId"]
	if !ok {
		return fmt.Errorf("document metadata is missing field 'canonicalId': %s", resp.Payload)
	}

	logger.Infof(".. successfully verified DID %s from %s", canonicalID, url)

	return nil
}

type createDIDRequest struct {
	url        string
	httpClient *httpClient
}

func (r *createDIDRequest) Invoke() (interface{}, error) {
	logger.Infof("creating DID document at %s", r.url)

	opaqueDoc, err := getOpaqueDocument("key1")
	if err != nil {
		return nil, err
	}

	_, _, reqBytes, err := getCreateRequest(r.url, opaqueDoc, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.httpClient.Post(r.url, reqBytes, "application/json")
	if err != nil {
		return "", err
	}

	logger.Infof("... got DID document: %s", resp.Payload)

	var rr document.ResolutionResult
	err = json.Unmarshal(resp.Payload, &rr)
	if err != nil {
		return "", err
	}

	return rr.Document.ID(), nil
}

// RegisterSteps registers orb steps
func (d *DIDOrbSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client discover orb endpoints$`, d.discoverEndpoints)
	s.Step(`^client sends request to "([^"]*)" to request anchor origin$`, d.clientRequestsAnchorOrigin)
	s.Step(`^client verifies resolved document$`, d.clientVerifiesResolvedDocument)
	s.Step(`^check error response contains "([^"]*)"$`, d.checkErrorResp)
	s.Step(`^client sends request to "([^"]*)" to create DID document$`, d.createDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to create DID document and the ID is saved to variable "([^"]*)"$`, d.createDIDDocumentSaveIDToVar)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessRespContains)
	s.Step(`^check success response does NOT contain "([^"]*)"$`, d.checkSuccessRespDoesntContain)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with interim did$`, d.resolveDIDDocumentWithInterimDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with canonical did$`, d.resolveDIDDocumentWithCanonicalDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with canonical did and resets keys to last successful$`, d.resetKeysToLastSuccessful)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with previous canonical did$`, d.resolveDIDDocumentWithPreviousCanonicalDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with invalid CID in canonical did$`, d.resolveDIDDocumentWithInvalidCIDInDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with equivalent did$`, d.resolveDIDDocumentWithEquivalentDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with previous equivalent did$`, d.resolveDIDDocumentWithPreviousEquivalentDID)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with hint "([^"]*)"`, d.resolveDIDDocumentWithHint)
	s.Step(`^client sends request to "([^"]*)" to resolve interim DID document with hint "([^"]*)"`, d.resolveInterimDIDDocumentWithHint)
	s.Step(`^client sends request to "([^"]*)" to add public key with ID "([^"]*)" to DID document$`, d.addPublicKeyToDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to remove public key with ID "([^"]*)" from DID document$`, d.removePublicKeyFromDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to add service endpoint with ID "([^"]*)" to DID document$`, d.addServiceEndpointToDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to remove service endpoint with ID "([^"]*)" from DID document$`, d.removeServiceEndpointsFromDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to deactivate DID document$`, d.deactivateDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to recover DID document$`, d.recoverDIDDocument)
	s.Step(`^client sends request to "([^"]*)" to resolve DID document with initial state$`, d.resolveDIDDocumentWithInitialValue)
	s.Step(`^check for request success`, d.checkResponseIsSuccess)
	s.Step(`^client sends request to "([^"]*)" to create (\d+) DID documents using (\d+) concurrent requests$`, d.createDIDDocuments)
	s.Step(`^client sends request to "([^"]*)" to verify the DID documents that were created$`, d.verifyDIDDocuments)
}
