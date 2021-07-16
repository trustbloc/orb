/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	mrand "math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
)

const (
	serviceID = "service"
	// P256KeyType EC P-256 key type.
	P256KeyType       = "P256"
	p384KeyType       = "P384"
	bls12381G2KeyType = "Bls12381G2"
	// Ed25519KeyType ed25519 key type.
	Ed25519KeyType = "Ed25519"
	masterKeyURI   = "local-lock://custom/master/key/"
)

// StressSteps is steps for orb stress BDD tests.
type StressSteps struct {
	bddContext *BDDContext
	localKMS   kms.KeyManager
}

// NewStressSteps returns new agent from client SDK.
func NewStressSteps(ctx *BDDContext) *StressSteps {
	sl := &noop.NoLock{} // for bdd tests, using no lock

	kmsProvider, err := ariescontext.New(ariescontext.WithStorageProvider(mem.NewProvider()),
		ariescontext.WithSecretLock(sl))
	if err != nil {
		panic(fmt.Errorf("failed to create new kms provider: %w", err))
	}

	km, err := localkms.New(masterKeyURI, kmsProvider)
	if err != nil {
		panic(fmt.Errorf("failed to create new kms: %w", err))
	}

	return &StressSteps{
		bddContext: ctx,
		localKMS:   km,
	}
}

// RegisterSteps registers agent steps.
func (e *StressSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to "([^"]*)" to create and update "([^"]*)" DID documents with anchor origin "([^"]*)" using "([^"]*)" concurrent requests$`,
		e.createConcurrentReq)
}

func (e *StressSteps) createConcurrentReq(domainsEnv, didNumsEnv, anchorOriginEnv, concurrencyEnv string) error {
	domains := os.Getenv(domainsEnv)
	if domains == "" {
		return fmt.Errorf("domains is empty")
	}

	anchorOrigin := os.Getenv(anchorOriginEnv)
	if domains == "" {
		return fmt.Errorf("anchorOrigin is empty")
	}

	didNumsStr := os.Getenv(didNumsEnv)
	if didNumsStr == "" {
		return fmt.Errorf("did nums is empty")
	}

	didNums, err := strconv.Atoi(didNumsStr)
	if err != nil {
		return err
	}

	concurrencyReqStr := os.Getenv(concurrencyEnv)
	if concurrencyReqStr == "" {
		return fmt.Errorf("concurrency nums is empty")
	}

	concurrencyReq, err := strconv.Atoi(concurrencyReqStr)
	if err != nil {
		return err
	}

	maxRetryStr := os.Getenv("ORB_STRESS_MAX_RETRY")
	if maxRetryStr == "" {
		maxRetryStr = "10"
	}

	maxRetry, err := strconv.Atoi(maxRetryStr)
	if err != nil {
		return err
	}

	urls := strings.Split(domains, ",")

	kr := &keyRetrieverMap{
		updateKey:             make(map[string]crypto.PrivateKey),
		nextUpdatePublicKey:   make(map[string]crypto.PublicKey),
		recoverKey:            make(map[string]crypto.PrivateKey),
		nextRecoveryPublicKey: make(map[string]crypto.PublicKey),
	}

	vdrs := make([]*orb.VDR, 0)

	for _, url := range urls {
		vdr, err := orb.New(kr, orb.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
			orb.WithDomain(url), orb.WithAuthToken("ADMIN_TOKEN"))
		if err != nil {
			return err
		}

		vdrs = append(vdrs, vdr)
	}

	p := NewWorkerPool(concurrencyReq)

	p.Start()

	for i := 0; i < didNums; i++ {
		randomVDR := vdrs[mrand.Intn(len(urls))]

		p.Submit(&createUpdateDIDRequest{
			vdr:          randomVDR,
			kr:           kr,
			anchorOrigin: anchorOrigin,
			steps:        e,
			maxRetry:     maxRetry,
		})
	}

	p.Stop()

	logger.Infof("got %d responses for %d requests", len(p.responses), didNums)

	if len(p.responses) != didNums {
		return fmt.Errorf("expecting %d responses but got %d", didNums, len(p.responses))
	}

	for _, resp := range p.responses {
		if resp.Err != nil {
			return resp.Err
		}
	}

	return nil
}

func (e *StressSteps) createVerificationMethod(keyType string, pubKey []byte, kid,
	signatureSuite string) (*ariesdid.VerificationMethod, error) {
	var jwk *jose.JWK

	var err error

	switch keyType {
	case P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)

		jwk, err = jose.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
		if err != nil {
			return nil, err
		}
	case p384KeyType:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKey)

		jwk, err = jose.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P384()})
		if err != nil {
			return nil, err
		}
	case bls12381G2KeyType:
		pk, e := bbs12381g2pub.UnmarshalPublicKey(pubKey)
		if e != nil {
			return nil, e
		}

		jwk, err = jose.JWKFromKey(pk)
		if err != nil {
			return nil, err
		}
	default:
		jwk, err = jose.JWKFromKey(ed25519.PublicKey(pubKey))
		if err != nil {
			return nil, err
		}
	}

	return ariesdid.NewVerificationMethodFromJWK(kid, signatureSuite, "", jwk)
}

func (e *StressSteps) createDID(keyType, signatureSuite, origin, svcEndpoint string, vdr *orb.VDR) (crypto.PrivateKey,
	crypto.PrivateKey, string, error) {
	kid, pubKey, err := e.getPublicKey(keyType)
	if err != nil {
		return nil, nil, "", err
	}

	recoveryKey, recoveryKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	vm, err := e.createVerificationMethod(keyType, pubKey, kid, signatureSuite)
	if err != nil {
		return nil, nil, "", err
	}

	didDoc := &ariesdid.Doc{}

	didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
		ariesdid.Authentication))

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey),
		vdrapi.WithOption(orb.AnchorOriginOpt, origin))
	if err != nil {
		return nil, nil, "", err
	}

	return recoveryKeyPrivateKey, updateKeyPrivateKey, createdDocResolution.DIDDocument.ID, nil
}

func (e *StressSteps) updateDID(didID string, origin, svcEndpoint string, vdr *orb.VDR) error {
	didDoc := &ariesdid.Doc{ID: didID}

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	return vdr.Update(didDoc,
		vdrapi.WithOption(orb.AnchorOriginOpt, origin))
}

func (e *StressSteps) getPublicKey(keyType string) (string, []byte, error) { //nolint:gocritic
	var kt kms.KeyType

	switch keyType {
	case Ed25519KeyType:
		kt = kms.ED25519Type
	case P256KeyType:
		kt = kms.ECDSAP256TypeIEEEP1363
	case p384KeyType:
		kt = kms.ECDSAP384TypeIEEEP1363
	case bls12381G2KeyType:
		kt = kms.BLS12381G2Type
	}

	return e.localKMS.CreateAndExportPubKeyBytes(kt)
}

type keyRetrieverMap struct {
	sync.RWMutex
	nextRecoveryPublicKey map[string]crypto.PublicKey
	nextUpdatePublicKey   map[string]crypto.PublicKey
	updateKey             map[string]crypto.PrivateKey
	recoverKey            map[string]crypto.PrivateKey
}

func (k *keyRetrieverMap) GetNextRecoveryPublicKey(didID string) (crypto.PublicKey, error) {
	k.RLock()
	defer k.RUnlock()
	return k.nextRecoveryPublicKey[didID], nil
}

func (k *keyRetrieverMap) GetNextUpdatePublicKey(didID string) (crypto.PublicKey, error) {
	k.RLock()
	defer k.RUnlock()
	return k.nextUpdatePublicKey[didID], nil
}

func (k *keyRetrieverMap) GetSigningKey(didID string, ot orb.OperationType) (crypto.PrivateKey, error) {
	k.RLock()
	defer k.RUnlock()
	if ot == orb.Update {
		return k.updateKey[didID], nil
	}

	return k.recoverKey[didID], nil
}

func (k *keyRetrieverMap) WriteKey(didID string, ot orb.OperationType, pk crypto.PrivateKey) {
	if ot == orb.Update {
		k.Lock()
		k.updateKey[didID] = pk
		k.Unlock()
	}

	k.Lock()
	k.recoverKey[didID] = pk
	k.Unlock()
}

func (k *keyRetrieverMap) WriteNextUpdatePublicKey(didID string, key crypto.PublicKey) {
	k.Lock()
	k.nextUpdatePublicKey[didID] = key
	k.Unlock()
}

type createUpdateDIDRequest struct {
	vdr          *orb.VDR
	kr           *keyRetrieverMap
	steps        *StressSteps
	anchorOrigin string
	maxRetry     int
}

func (r *createUpdateDIDRequest) Invoke() (interface{}, error) {
	recoveryKeyPrivateKey, updateKeyPrivateKey, intermID, err := r.steps.createDID("Ed25519",
		"Ed25519VerificationKey2018", r.anchorOrigin, uuid.New().URN(), r.vdr)
	if err != nil {
		return nil, err
	}

	logger.Infof("created did successfully %s", intermID)
	logger.Infof("started resolving created did %s", intermID)

	var docResolution *ariesdid.DocResolution

	for i := 1; i <= r.maxRetry; i++ {
		var err error
		docResolution, err = r.vdr.Read(intermID)

		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "DID does not exist") || i == r.maxRetry {
			return nil, err
		}

		time.Sleep(1 * time.Second)
	}

	canonicalID := docResolution.DocumentMetadata.CanonicalID

	logger.Infof("resolved created did successfully %s", canonicalID)

	r.kr.WriteKey(canonicalID, orb.Recover, recoveryKeyPrivateKey)
	r.kr.WriteKey(canonicalID, orb.Update, updateKeyPrivateKey)

	nextUpdatePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	r.kr.WriteNextUpdatePublicKey(canonicalID, nextUpdatePublicKey)

	svcEndpoint := uuid.New().URN()

	if err := r.steps.updateDID(canonicalID, r.anchorOrigin, svcEndpoint, r.vdr); err != nil {
		return nil, err
	}

	logger.Infof("update did successfully %s", canonicalID)
	logger.Infof("started resolving updated did %s", canonicalID)

	for i := 1; i <= r.maxRetry; i++ {
		var err error
		docResolution, err = r.vdr.Read(canonicalID)

		if err == nil && docResolution.DIDDocument.Service[0].ServiceEndpoint == svcEndpoint {
			break
		}

		if i == r.maxRetry {
			return nil, fmt.Errorf("update did not working %s", canonicalID)
		}

		time.Sleep(1 * time.Second)
	}

	logger.Infof("resolved updated did successfully %s %s", intermID, canonicalID)

	return nil, nil
}
