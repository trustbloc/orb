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

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"

	"github.com/hyperledger/aries-framework-go/pkg/common/model"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/greenpau/go-calculator"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/trustbloc/sidetree-go/pkg/jws"
	"github.com/trustbloc/sidetree-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-go/pkg/versions/1_0/client"
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

var (
	createHTTPTime        []int64
	createLogCount        int64
	createCount           int64
	resolveCreateHTTPTime []int64
	resolveCreateLogCount int64
	resolveCreateCount    int64
	updateHTTPTime        []int64
	updateLogCount        int64
	updateCount           int64
	resolveUpdateHTTPTime []int64
	resolveUpdateLogCount int64
	resolveUpdateCount    int64
)

// StressSteps is steps for orb stress BDD tests.
type StressSteps struct {
	bddContext *BDDContext
	localKMS   kms.KeyManager
}

type kmsProvider struct {
	kmsStore          kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.kmsStore
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

// NewStressSteps returns new agent from client SDK.
func NewStressSteps(ctx *BDDContext) *StressSteps {
	sl := &noop.NoLock{} // for bdd tests, using no lock

	kmsStore, err := kms.NewAriesProviderWrapper(mem.NewProvider())
	if err != nil {
		panic(fmt.Errorf("failed to create Aries KMS store wrapper: %w", err))
	}

	kmsProv := &kmsProvider{
		kmsStore:          kmsStore,
		secretLockService: sl,
	}

	km, err := localkms.New(masterKeyURI, kmsProv)
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
	s.Step(`^client sends request to "([^"]*)" to create and update "([^"]*)" DID documents using "([^"]*)" concurrent requests with auth token "([^"]*)"$`,
		e.createConcurrentReq)
}

func (e *StressSteps) createConcurrentReq(domainsEnv, didNumsEnv, concurrencyEnv, authTokenEnv string) error {
	domains := os.Getenv(domainsEnv)
	if domains == "" {
		return fmt.Errorf("domains is empty")
	}

	didNumsStr := os.Getenv(didNumsEnv)
	if didNumsStr == "" {
		return fmt.Errorf("did nums is empty")
	}

	authTokenStr := os.Getenv(authTokenEnv)
	if authTokenStr == "" {
		return fmt.Errorf("auth token is empty")
	}

	didNums, err := strconv.Atoi(didNumsStr)
	if err != nil {
		return err
	}

	didNums = didNums / 2

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
		orb.WithAuthToken(authTokenStr), orb.WithVerifyResolutionResultType(orb.Unpublished))

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

	fmt.Println("start pre test creating did")

	preTestCreatePool := NewWorkerPool[*createDIDResp](concurrencyReq)

	preTestCreatePool.Start()

	for i := 0; i < didNums; i++ {
		preTestCreatePool.Submit(&createDIDReq{
			vdr:              vdr,
			steps:            e,
			verMethodsCreate: verMethodsCreate,
		})
	}

	preTestCreatePool.Stop()

	logger.Infof("pre test: got created %d responses for %d requests", len(preTestCreatePool.responses), didNums)

	if len(preTestCreatePool.responses) != didNums {
		return fmt.Errorf("pre test: expecting created %d responses but got %d", didNums, len(preTestCreatePool.responses))
	}

	preTestResolvePool := NewWorkerPool[*resolveDIDResp](concurrencyReq)

	preTestResolvePool.Start()

	anchoredDID := make([]string, 0)

	for _, resp := range preTestCreatePool.responses {
		if resp.Err != nil {
			return resp.Err
		}

		r := resp.Resp

		preTestResolvePool.Submit(&resolveDIDReq{
			vdr:                   vdr,
			kr:                    kr,
			maxRetry:              maxRetry,
			intermID:              r.intermID,
			recoveryKeyPrivateKey: r.recoveryKeyPrivateKey,
			updateKeyPrivateKey:   r.updateKeyPrivateKey,
			checkForPublished:     true,
		})

	}

	preTestResolvePool.Stop()

	logger.Infof("pre test: got resolved created %d responses for %d requests", len(preTestResolvePool.responses), didNums)

	if len(preTestResolvePool.responses) != didNums {
		return fmt.Errorf("pre test: expecting resolved created %d responses but got %d", didNums, len(preTestResolvePool.responses))
	}

	for _, resp := range preTestResolvePool.responses {
		if resp.Err != nil {
			return resp.Err
		}

		anchoredDID = append(anchoredDID, resp.Resp.canonicalID)
	}

	createHTTPTime = make([]int64, 0)
	resolveCreateHTTPTime = make([]int64, 0)
	resolveCreateLogCount = 0
	createLogCount = 0

	fmt.Println("finish pre test creating did")

	testPool := NewWorkerPool[interface{}](concurrencyReq)

	testPool.Start()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		for i := 0; i < didNums; i++ {
			testPool.Submit(&createResolveDIDReq{
				vdr:               vdr,
				steps:             e,
				verMethodsCreate:  verMethodsCreate,
				kr:                kr,
				maxRetry:          maxRetry,
				checkForPublished: false,
			})
		}

		wg.Done()
	}()

	go func() {
		for i := 0; i < len(anchoredDID); i++ {
			testPool.Submit(&updateResolveDIDReq{
				vdr:              vdr,
				canonicalID:      anchoredDID[i],
				kr:               kr,
				steps:            e,
				verMethodsCreate: verMethodsCreate,
				verMethodsUpdate: verMethodsUpdate,
				maxRetry:         maxRetry,
			})
		}

		wg.Done()
	}()

	wg.Wait()

	testPool.Stop()

	if len(testPool.responses) != didNums*2 {
		return fmt.Errorf("expecting responses %d but got %d", didNums*2, len(preTestCreatePool.responses))
	}

	for _, resp := range testPool.responses {
		if resp.Err != nil {
			return resp.Err
		}
	}

	fmt.Printf("finished test with DID %d concurrent %d\n", len(testPool.responses), concurrencyReq)

	calc := calculator.NewInt64(createHTTPTime)
	fmt.Printf("vdr create DID avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("vdr create DID max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("vdr create DID min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(resolveCreateHTTPTime)
	fmt.Printf("vdr resolve create DID avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("vdr resolve create DID max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("vdr resolve create DID min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(updateHTTPTime)
	fmt.Printf("vdr update DID avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("vdr update DID max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("vdr update DID min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	calc = calculator.NewInt64(resolveUpdateHTTPTime)
	fmt.Printf("vdr resolve update DID avg time: %s\n", (time.Duration(calc.Mean().Register.Mean) *
		time.Millisecond).String())
	fmt.Printf("vdr resolve update DID max time: %s\n", (time.Duration(calc.Max().Register.MaxValue) *
		time.Millisecond).String())
	fmt.Printf("vdr resolve update DID min time: %s\n", (time.Duration(calc.Min().Register.MinValue) *
		time.Millisecond).String())
	fmt.Println("------")

	return nil
}

func (e *StressSteps) createVerificationMethod(keyType string, pubKey []byte, kid,
	signatureSuite string,
) (*ariesdid.VerificationMethod, error) {
	var jwk *jwk.JWK

	var err error

	switch keyType {
	case P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKey) //nolint:staticcheck

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
	crypto.PrivateKey, string, error,
) {
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

	didDoc.Service = []ariesdid.Service{{
		ID: serviceID, Type: "type",
		ServiceEndpoint: model.NewDIDCommV1Endpoint(svcEndpoint),
	}}

	startTime := time.Now()

	createdDocResolution, err := vdr.Create(didDoc,
		vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey))
	if err != nil {
		return nil, nil, "", err
	}

	endTime := time.Since(startTime)
	endTimeMS := endTime.Milliseconds()

	createHTTPTime = append(createHTTPTime, endTimeMS)

	return recoveryKeyPrivateKey, updateKeyPrivateKey, createdDocResolution.DocumentMetadata.EquivalentID[0], nil
}

func (e *StressSteps) updateDID(didID string, svcEndpoint string, vdr *orb.VDR,
	verMethodsCreate []*ariesdid.VerificationMethod, verMethodsUpdate []*ariesdid.VerificationMethod,
) error {
	didDoc := &ariesdid.Doc{ID: didID}

	didDoc.Service = []ariesdid.Service{
		{
			ID:              serviceID,
			Type:            "type",
			ServiceEndpoint: model.NewDIDCommV1Endpoint(svcEndpoint),
		},
	}

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

func (k *keyRetrieverMap) GetSigner(didID string, ot orb.OperationType, commitment string) (api.Signer, error) {
	k.RLock()
	defer k.RUnlock()

	if ot == orb.Update {
		return newSignerMock(k.updateKey[didID]), nil
	}

	return newSignerMock(k.recoverKey[didID]), nil
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

type createResolveDIDReq struct {
	vdr               *orb.VDR
	steps             *StressSteps
	verMethodsCreate  []*ariesdid.VerificationMethod
	kr                *keyRetrieverMap
	maxRetry          int
	checkForPublished bool
}

func (r *createResolveDIDReq) URL() string {
	return ""
}

func (r *createResolveDIDReq) Invoke() (interface{}, error) {
	createReq := &createDIDReq{
		vdr:              r.vdr,
		steps:            r.steps,
		verMethodsCreate: r.verMethodsCreate,
	}

	createResp, err := createReq.Invoke()
	if err != nil {
		return nil, err
	}

	resolveReq := &resolveDIDReq{
		vdr:                   r.vdr,
		kr:                    r.kr,
		maxRetry:              r.maxRetry,
		intermID:              createResp.intermID,
		recoveryKeyPrivateKey: createResp.recoveryKeyPrivateKey,
		updateKeyPrivateKey:   createResp.updateKeyPrivateKey,
		checkForPublished:     r.checkForPublished,
	}

	_, err = resolveReq.Invoke()
	if err != nil {
		return nil, err
	}

	return nil, nil
}

type updateResolveDIDReq struct {
	vdr              *orb.VDR
	canonicalID      string
	kr               *keyRetrieverMap
	steps            *StressSteps
	verMethodsCreate []*ariesdid.VerificationMethod
	verMethodsUpdate []*ariesdid.VerificationMethod
	maxRetry         int
}

func (r *updateResolveDIDReq) URL() string {
	return ""
}

func (r *updateResolveDIDReq) Invoke() (interface{}, error) {
	updateReq := &updateDIDReq{
		vdr:              r.vdr,
		steps:            r.steps,
		canonicalID:      r.canonicalID,
		kr:               r.kr,
		verMethodsCreate: r.verMethodsCreate,
		verMethodsUpdate: r.verMethodsUpdate,
	}

	updateResp, err := updateReq.Invoke()
	if err != nil {
		return nil, err
	}

	resolveReq := resolveUpdatedDIDReq{
		vdr:         r.vdr,
		maxRetry:    r.maxRetry,
		canonicalID: updateResp.canonicalID,
		svcEndpoint: updateResp.svcEndpoint,
	}

	_, err = resolveReq.Invoke()
	if err != nil {
		return nil, err
	}

	return nil, nil
}

type createDIDReq struct {
	vdr              *orb.VDR
	steps            *StressSteps
	verMethodsCreate []*ariesdid.VerificationMethod
}

type createDIDResp struct {
	intermID              string
	recoveryKeyPrivateKey crypto.PrivateKey
	updateKeyPrivateKey   crypto.PrivateKey
}

func (r *createDIDReq) URL() string {
	return ""
}

func (r *createDIDReq) Invoke() (*createDIDResp, error) {
	var recoveryKeyPrivateKey, updateKeyPrivateKey crypto.PrivateKey
	var intermID string
	var err error

	for i := 1; i <= 10; i++ {
		recoveryKeyPrivateKey, updateKeyPrivateKey, intermID, err = r.steps.createDID(r.verMethodsCreate,
			uuid.New().URN(), r.vdr)

		atomic.AddInt64(&createCount, 1)
		if err == nil {
			break
		}

		if !checkRetryError(err) {
			return nil, fmt.Errorf("failed to create did: %w", err)
		}
	}

	if atomic.AddInt64(&createLogCount, 1)%1000 == 0 {
		logger.Infof("created did successfully %d", createLogCount)
	}

	return &createDIDResp{
		intermID:              intermID,
		recoveryKeyPrivateKey: recoveryKeyPrivateKey,
		updateKeyPrivateKey:   updateKeyPrivateKey,
	}, nil
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
	canonicalID string
	svcEndpoint string
}

func (r *updateDIDReq) Invoke() (*updateDIDResp, error) {
	nextUpdatePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	r.kr.WriteNextUpdatePublicKey(r.canonicalID, nextUpdatePublicKey)

	svcEndpoint := uuid.New().URN()

	for i := 1; i <= 10; i++ {
		startTime := time.Now()

		err := r.steps.updateDID(r.canonicalID, svcEndpoint, r.vdr, r.verMethodsCreate, r.verMethodsUpdate)

		atomic.AddInt64(&updateCount, 1)

		endTime := time.Since(startTime)
		endTimeMS := endTime.Milliseconds()

		updateHTTPTime = append(updateHTTPTime, endTimeMS)

		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "DID does not exist") && !checkRetryError(err) {
			return nil, fmt.Errorf("failed to update did: %w", err)
		}
	}

	if atomic.AddInt64(&updateLogCount, 1)%1000 == 0 {
		logger.Infof("updated did successfully %d", updateLogCount)
	}

	return &updateDIDResp{canonicalID: r.canonicalID, svcEndpoint: svcEndpoint}, nil
}

type resolveDIDReq struct {
	vdr                   *orb.VDR
	kr                    *keyRetrieverMap
	maxRetry              int
	intermID              string
	recoveryKeyPrivateKey crypto.PrivateKey
	updateKeyPrivateKey   crypto.PrivateKey
	checkForPublished     bool
}

type resolveDIDResp struct {
	canonicalID string
}

func (r *resolveDIDReq) URL() string {
	return ""
}

func (r *resolveDIDReq) Invoke() (*resolveDIDResp, error) {
	var docResolution *ariesdid.DocResolution

	for i := 1; i <= r.maxRetry; i++ {
		var err error

		startTime := time.Now()

		docResolution, err = r.vdr.Read(r.intermID)

		atomic.AddInt64(&resolveCreateCount, 1)

		endTime := time.Since(startTime)
		endTimeMS := endTime.Milliseconds()

		resolveCreateHTTPTime = append(resolveCreateHTTPTime, endTimeMS)

		if err == nil && (docResolution.DocumentMetadata.Method.Published || !r.checkForPublished) {
			break
		}

		if err != nil && !strings.Contains(err.Error(), "DID does not exist") &&
			!checkRetryError(err) {
			return nil, fmt.Errorf("failed to resolve create did: %s", err.Error())
		}

		if i == r.maxRetry {
			if err == nil {
				return nil, fmt.Errorf("did is not published %s", r.intermID)
			}

			return nil, fmt.Errorf("failed resolve created DID %s: %s", r.intermID, err.Error())
		}

		time.Sleep(1 * time.Second)
	}

	canonicalID := docResolution.DocumentMetadata.CanonicalID

	r.kr.WriteKey(canonicalID, orb.Recover, r.recoveryKeyPrivateKey)
	r.kr.WriteKey(canonicalID, orb.Update, r.updateKeyPrivateKey)

	if atomic.AddInt64(&resolveCreateLogCount, 1)%1000 == 0 {
		logger.Infof("resolved created did successfully %d", resolveCreateLogCount)
	}

	return &resolveDIDResp{canonicalID: canonicalID}, nil
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

		startTime := time.Now()

		docResolution, err = r.vdr.Read(r.canonicalID)

		atomic.AddInt64(&resolveUpdateCount, 1)

		endTime := time.Since(startTime)
		endTimeMS := endTime.Milliseconds()

		resolveUpdateHTTPTime = append(resolveUpdateHTTPTime, endTimeMS)

		if err == nil {
			uri, err := docResolution.DIDDocument.Service[0].ServiceEndpoint.URI()
			if err != nil {
				return nil, err
			}

			if uri == r.svcEndpoint {
				break
			}
		}

		if err != nil && !checkRetryError(err) {
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

	if atomic.AddInt64(&resolveUpdateLogCount, 1)%1000 == 0 {
		logger.Infof("resolved updated did successfully %d", resolveUpdateLogCount)
	}

	return nil, nil
}

func checkRetryError(err error) bool {
	if strings.Contains(err.Error(), "client connection force closed") ||
		strings.Contains(err.Error(), "server sent GOAWAY and closed the connection") ||
		strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "502 Bad Gateway") {
		return true
	}

	return false
}

type signerMock struct {
	signer    client.Signer
	publicKey *jws.JWK
}

func newSignerMock(signingkey crypto.PrivateKey) *signerMock {
	switch key := signingkey.(type) {
	case *ecdsa.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			panic(err.Error())
		}

		return &signerMock{signer: ecsigner.New(key, "ES256", "k1"), publicKey: updateKey}
	case ed25519.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			panic(err.Error())
		}

		return &signerMock{signer: edsigner.New(key, "EdDSA", "k1"), publicKey: updateKey}
	}

	return nil
}

func (s *signerMock) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

func (s *signerMock) Headers() jws.Headers {
	return s.signer.Headers()
}

func (s *signerMock) PublicKeyJWK() *jws.JWK {
	return s.publicKey
}
