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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
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

var createLogCount int64
var resolveCreateLogCount int64
var updateLogCount int64
var resolveUpdateLogCount int64

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
	s.Step(`^client sends request to "([^"]*)" to create and update "([^"]*)" DID documents using "([^"]*)" concurrent requests$`,
		e.createConcurrentReq)
}

func (e *StressSteps) createConcurrentReq(domainsEnv, didNumsEnv, concurrencyEnv string) error {
	domains := os.Getenv(domainsEnv)
	if domains == "" {
		return fmt.Errorf("domains is empty")
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

	orbOpts := make([]orb.Option, 0)

	for _, url := range urls {
		orbOpts = append(orbOpts, orb.WithDomain(url))
	}

	orbOpts = append(orbOpts, orb.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
		orb.WithAuthToken("ADMIN_TOKEN"))

	vdr, err := orb.New(kr, orbOpts...)
	if err != nil {
		return err
	}

	verMethodsCreate := make([]*ariesdid.VerificationMethod, 0)
	verMethodsUpdate := make([]*ariesdid.VerificationMethod, 0)

	for i := 1; i < 7; i++ {
		kid, pubKey, err := e.getPublicKey("Ed25519")
		if err != nil {
			return err
		}

		vm, err := e.createVerificationMethod("Ed25519", pubKey, kid, "Ed25519VerificationKey2018")
		if err != nil {
			return err
		}

		verMethodsCreate = append(verMethodsCreate, vm)
	}

	for i := 1; i < 3; i++ {
		kid, pubKey, err := e.getPublicKey("Ed25519")
		if err != nil {
			return err
		}

		vm, err := e.createVerificationMethod("Ed25519", pubKey, kid, "Ed25519VerificationKey2018")
		if err != nil {
			return err
		}

		verMethodsUpdate = append(verMethodsUpdate, vm)
	}

	createPool := NewWorkerPool(concurrencyReq)

	createPool.Start()

	createStart := time.Now()

	for i := 0; i < didNums; i++ {
		createPool.Submit(&createDIDReq{
			vdr:              vdr,
			steps:            e,
			verMethodsCreate: verMethodsCreate,
		})
	}

	createPool.Stop()

	logger.Infof("got created %d responses for %d requests", len(createPool.responses), didNums)

	if len(createPool.responses) != didNums {
		return fmt.Errorf("expecting created %d responses but got %d", didNums, len(createPool.responses))
	}

	createTimeStr := time.Since(createStart).String()

	resolvePool := NewWorkerPool(concurrencyReq)

	resolvePool.Start()

	resolveStart := time.Now()

	for _, resp := range createPool.responses {
		if resp.Err != nil {
			return resp.Err
		}

		r, ok := resp.Resp.(createDIDResp)
		if !ok {
			return fmt.Errorf("failed to cast resp to createDIDResp")
		}

		resolvePool.Submit(&resolveDIDReq{
			vdr:                   r.vdr,
			kr:                    kr,
			maxRetry:              maxRetry,
			intermID:              r.intermID,
			recoveryKeyPrivateKey: r.recoveryKeyPrivateKey,
			updateKeyPrivateKey:   r.updateKeyPrivateKey,
		})

	}

	resolvePool.Stop()

	logger.Infof("got resolved created %d responses for %d requests", len(resolvePool.responses), didNums)

	if len(resolvePool.responses) != didNums {
		return fmt.Errorf("expecting resolved created %d responses but got %d", didNums, len(resolvePool.responses))
	}

	resolveTimeStr := time.Since(resolveStart).String()

	for _, resp := range resolvePool.responses {
		if resp.Err != nil {
			return resp.Err
		}
	}

	// update did

	updatePool := NewWorkerPool(concurrencyReq)

	updatePool.Start()

	updateStart := time.Now()

	for _, resp := range resolvePool.responses {
		r, ok := resp.Resp.(resolveDIDResp)
		if !ok {
			return fmt.Errorf("failed to cast resp to createDIDResp")
		}

		updatePool.Submit(&updateDIDReq{
			vdr:              r.vdr,
			steps:            e,
			canonicalID:      r.canonicalID,
			kr:               kr,
			verMethodsCreate: verMethodsCreate,
			verMethodsUpdate: verMethodsUpdate,
		})
	}

	updatePool.Stop()

	logger.Infof("got updated %d responses for %d requests", len(updatePool.responses), didNums)

	if len(updatePool.responses) != didNums {
		return fmt.Errorf("expecting updated %d responses but got %d", didNums, len(updatePool.responses))
	}

	updateTimeStr := time.Since(updateStart).String()

	resolveUpdatePool := NewWorkerPool(concurrencyReq)

	resolveUpdatePool.Start()

	resolveUpdateStart := time.Now()

	for _, resp := range updatePool.responses {
		if resp.Err != nil {
			return resp.Err
		}

		r, ok := resp.Resp.(updateDIDResp)
		if !ok {
			return fmt.Errorf("failed to cast resp to updateDIDResp")
		}

		resolveUpdatePool.Submit(&resolveUpdatedDIDReq{
			vdr:         r.vdr,
			maxRetry:    maxRetry,
			canonicalID: r.canonicalID,
			svcEndpoint: r.svcEndpoint,
		})

	}

	resolveUpdatePool.Stop()

	logger.Infof("got resolved updated %d responses for %d requests", len(resolveUpdatePool.responses), didNums)

	if len(resolveUpdatePool.responses) != didNums {
		return fmt.Errorf("expecting resolved updated %d responses but got %d", didNums, len(resolveUpdatePool.responses))
	}

	resolveUpdateTimeStr := time.Since(resolveUpdateStart).String()

	for _, resp := range resolveUpdatePool.responses {
		if resp.Err != nil {
			return resp.Err
		}
	}

	fmt.Printf("Created did %d took: %s\n", didNums, createTimeStr)
	fmt.Println("------")

	fmt.Printf("Resolved anchor did %d took: %s\n", didNums, resolveTimeStr)
	fmt.Println("------")

	fmt.Printf("Updated did %d took: %s\n", didNums, updateTimeStr)
	fmt.Println("------")

	fmt.Printf("Resolved updated did %d took: %s\n", didNums, resolveUpdateTimeStr)
	fmt.Println("------")

	return nil
}

func (e *StressSteps) createVerificationMethod(keyType string, pubKey []byte, kid,
	signatureSuite string) (*ariesdid.VerificationMethod, error) {
	var jwk *jwk.JWK

	var err error

	switch keyType {
	case P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey)

		jwk, err = jwksupport.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()})
		if err != nil {
			return nil, err
		}
	case p384KeyType:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKey)

		jwk, err = jwksupport.JWKFromKey(&ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P384()})
		if err != nil {
			return nil, err
		}
	case bls12381G2KeyType:
		pk, e := bbs12381g2pub.UnmarshalPublicKey(pubKey)
		if e != nil {
			return nil, e
		}

		jwk, err = jwksupport.JWKFromKey(pk)
		if err != nil {
			return nil, err
		}
	default:
		jwk, err = jwksupport.JWKFromKey(ed25519.PublicKey(pubKey))
		if err != nil {
			return nil, err
		}
	}

	return ariesdid.NewVerificationMethodFromJWK(kid, signatureSuite, "", jwk)
}

func (e *StressSteps) createDID(verMethodsCreate []*ariesdid.VerificationMethod,
	svcEndpoint string, vdr *orb.VDR) (crypto.PrivateKey,
	crypto.PrivateKey, string, error) {

	recoveryKey, recoveryKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	updateKey, updateKeyPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	didDoc := &ariesdid.Doc{}

	for _, vm := range verMethodsCreate {
		didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
			ariesdid.Authentication))
	}

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey))
	if err != nil {
		return nil, nil, "", err
	}

	return recoveryKeyPrivateKey, updateKeyPrivateKey, createdDocResolution.DIDDocument.ID, nil
}

func (e *StressSteps) updateDID(didID string, svcEndpoint string, vdr *orb.VDR,
	verMethodsCreate []*ariesdid.VerificationMethod, verMethodsUpdate []*ariesdid.VerificationMethod) error {
	didDoc := &ariesdid.Doc{ID: didID}

	didDoc.Service = []ariesdid.Service{{ID: serviceID, Type: "type", ServiceEndpoint: svcEndpoint}}

	for _, vm := range verMethodsCreate {
		didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
			ariesdid.Authentication))
	}

	for _, vm := range verMethodsUpdate {
		didDoc.Authentication = append(didDoc.Authentication, *ariesdid.NewReferencedVerification(vm,
			ariesdid.Authentication))
	}

	return vdr.Update(didDoc)
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

func (k *keyRetrieverMap) GetNextRecoveryPublicKey(didID string, commitment string) (crypto.PublicKey, error) {
	k.RLock()
	defer k.RUnlock()
	return k.nextRecoveryPublicKey[didID], nil
}

func (k *keyRetrieverMap) GetNextUpdatePublicKey(didID string, commitment string) (crypto.PublicKey, error) {
	k.RLock()
	defer k.RUnlock()
	return k.nextUpdatePublicKey[didID], nil
}

func (k *keyRetrieverMap) GetSigningKey(didID string, ot orb.OperationType,
	commitment string) (crypto.PrivateKey, error) {
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

type createDIDReq struct {
	vdr              *orb.VDR
	steps            *StressSteps
	verMethodsCreate []*ariesdid.VerificationMethod
}

type createDIDResp struct {
	vdr                   *orb.VDR
	intermID              string
	recoveryKeyPrivateKey crypto.PrivateKey
	updateKeyPrivateKey   crypto.PrivateKey
}

func (r *createDIDReq) Invoke() (interface{}, error) {
	var recoveryKeyPrivateKey, updateKeyPrivateKey crypto.PrivateKey
	var intermID string
	var err error

	for i := 1; i <= 10; i++ {
		recoveryKeyPrivateKey, updateKeyPrivateKey, intermID, err = r.steps.createDID(r.verMethodsCreate,
			uuid.New().URN(), r.vdr)
		if err == nil {
			break
		}

		logger.Errorf("error create DID %s", err.Error())

		if !strings.Contains(err.Error(), "cannot assign requested address") &&
			!strings.Contains(err.Error(), "connection timed out") {
			return nil, fmt.Errorf("failed to create did: %w", err)
		}
	}

	if atomic.AddInt64(&createLogCount, 1)%100 == 0 {
		logger.Infof("created did successfully %d", createLogCount)
	}

	return createDIDResp{vdr: r.vdr, intermID: intermID, recoveryKeyPrivateKey: recoveryKeyPrivateKey, updateKeyPrivateKey: updateKeyPrivateKey}, nil
}

type updateDIDReq struct {
	vdr              *orb.VDR
	canonicalID      string
	kr               *keyRetrieverMap
	steps            *StressSteps
	verMethodsCreate []*ariesdid.VerificationMethod
	verMethodsUpdate []*ariesdid.VerificationMethod
}

type updateDIDResp struct {
	vdr         *orb.VDR
	canonicalID string
	svcEndpoint string
}

func (r *updateDIDReq) Invoke() (interface{}, error) {
	nextUpdatePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	r.kr.WriteNextUpdatePublicKey(r.canonicalID, nextUpdatePublicKey)

	svcEndpoint := uuid.New().URN()

	for i := 1; i <= 10; i++ {
		err := r.steps.updateDID(r.canonicalID, svcEndpoint, r.vdr, r.verMethodsCreate, r.verMethodsUpdate)
		if err == nil {
			break
		}

		logger.Errorf("error updated DID %s: %s", r.canonicalID, err.Error())

		if !strings.Contains(err.Error(), "cannot assign requested address") &&
			!strings.Contains(err.Error(), "connection timed out") {
			return nil, fmt.Errorf("failed to update did: %w", err)
		}
	}

	if atomic.AddInt64(&updateLogCount, 1)%100 == 0 {
		logger.Infof("updated did successfully %d", updateLogCount)
	}

	return updateDIDResp{vdr: r.vdr, canonicalID: r.canonicalID, svcEndpoint: svcEndpoint}, nil
}

type resolveDIDReq struct {
	vdr                   *orb.VDR
	kr                    *keyRetrieverMap
	maxRetry              int
	intermID              string
	recoveryKeyPrivateKey crypto.PrivateKey
	updateKeyPrivateKey   crypto.PrivateKey
}

type resolveDIDResp struct {
	vdr         *orb.VDR
	canonicalID string
}

func (r *resolveDIDReq) Invoke() (interface{}, error) {
	var docResolution *ariesdid.DocResolution

	for i := 1; i <= r.maxRetry; i++ {
		var err error

		docResolution, err = r.vdr.Read(r.intermID)

		if err == nil && docResolution.DocumentMetadata.Method.Published {
			break
		}

		if err != nil && !strings.Contains(err.Error(), "DID does not exist") {
			logger.Errorf("resolve created DID %s: %s", r.intermID, err.Error())
		}

		if err != nil && !strings.Contains(err.Error(), "DID does not exist") &&
			!strings.Contains(err.Error(), "cannot assign requested address") &&
			!strings.Contains(err.Error(), "connection timed out") {
			return nil, err
		}

		if i == r.maxRetry {
			if err == nil {
				return nil, fmt.Errorf("did is not published")
			}

			return nil, err
		}

		time.Sleep(1 * time.Second)
	}

	canonicalID := docResolution.DocumentMetadata.CanonicalID

	r.kr.WriteKey(canonicalID, orb.Recover, r.recoveryKeyPrivateKey)
	r.kr.WriteKey(canonicalID, orb.Update, r.updateKeyPrivateKey)

	if atomic.AddInt64(&resolveCreateLogCount, 1)%100 == 0 {
		logger.Infof("resolved created did successfully %d", resolveCreateLogCount)
	}

	return resolveDIDResp{vdr: r.vdr, canonicalID: canonicalID}, nil
}

type resolveUpdatedDIDReq struct {
	vdr         *orb.VDR
	maxRetry    int
	canonicalID string
	svcEndpoint string
}

func (r *resolveUpdatedDIDReq) Invoke() (interface{}, error) {
	var docResolution *ariesdid.DocResolution

	for i := 1; i <= r.maxRetry; i++ {
		var err error
		docResolution, err = r.vdr.Read(r.canonicalID)

		if err == nil && docResolution.DIDDocument.Service[0].ServiceEndpoint == r.svcEndpoint {
			break
		}

		if err != nil {
			logger.Errorf("error resolve updated DID %s: %s", r.canonicalID, err.Error())
		}

		if err != nil &&
			!strings.Contains(err.Error(), "cannot assign requested address") &&
			!strings.Contains(err.Error(), "connection timed out") {
			return nil, err
		}

		if i == r.maxRetry {
			if err == nil {
				return nil, fmt.Errorf("did is not updated")
			}

			return nil, err
		}

		time.Sleep(1 * time.Second)
	}

	if atomic.AddInt64(&resolveUpdateLogCount, 1)%100 == 0 {
		logger.Infof("resolved updated did successfully %d", resolveUpdateLogCount)
	}

	return nil, nil
}
