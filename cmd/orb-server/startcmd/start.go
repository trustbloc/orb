/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/tink/go/subtle/random"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmysqlstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"

	aphandler "github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apservice "github.com/trustbloc/orb/pkg/activitypub/service"
	apspi "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	apmemstore "github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/handler"
	"github.com/trustbloc/orb/pkg/anchor/proofs"
	"github.com/trustbloc/orb/pkg/anchor/writer"
	"github.com/trustbloc/orb/pkg/config"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	"github.com/trustbloc/orb/pkg/context/cas"
	"github.com/trustbloc/orb/pkg/context/common"
	orbpc "github.com/trustbloc/orb/pkg/context/protocol/client"
	orbpcp "github.com/trustbloc/orb/pkg/context/protocol/provider"
	"github.com/trustbloc/orb/pkg/didanchorref/memdidanchorref"
	localdiscovery "github.com/trustbloc/orb/pkg/discovery/did/local"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/protocolversion/factoryregistry"
	"github.com/trustbloc/orb/pkg/resolver"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

const (
	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	masterKeyNumBytes = 32

	chBuffer = 100

	defaultMaxWitnessDelay = 10 * time.Minute
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/v1"

	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"

	activityPubServicesPath     = "/services/orb"
	activityPubTransactionsPath = "/transactions"

	casPath = "/cas"
)

type server interface {
	Start(srv *httpserver.Server) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct {
	activityPubService apspi.ServiceLifecycle
}

// Start starts the http server
func (s *HTTPServer) Start(srv *httpserver.Server) error {
	s.activityPubService.Start()

	if err := srv.Start(); err != nil {
		return err
	}

	logger.Infof("started orb rest service")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	s.activityPubService.Stop()

	return nil
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd() *cobra.Command {
	startCmd := createStartCmd()

	createFlags(startCmd)

	return startCmd
}

func createStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start orb-server",
		Long:  "Start orb-server",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getOrbParameters(cmd)
			if err != nil {
				return err
			}

			return startOrbServices(parameters)
		},
	}
}

// nolint: gocyclo,funlen,gocognit
func startOrbServices(parameters *orbParameters) error {
	if parameters.logLevel != "" {
		SetDefaultLogLevel(logger, parameters.logLevel)
	}

	storeProviders, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	localKMS, err := createKMS(storeProviders.kmsSecretsProvider)
	if err != nil {
		return err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return err
	}

	// basic providers (CAS + operation store)
	casClient := cas.New(parameters.casURL)

	didAnchors := memdidanchorref.New()
	opStore := mocks.NewMockOperationStore()

	orbDocumentLoader, err := loadOrbContexts()
	if err != nil {
		return fmt.Errorf("failed to load Orb contexts: %s", err.Error())
	}

	graphProviders := &graph.Providers{
		Cas: casClient,
		// TODO: For now fetch signing public key from local KMS (this will handled differently later on: webfinger or did:web)
		Pkf: func(_, keyID string) (*verifier.PublicKey, error) {
			kid := keyID[1:]

			pubKeyBytes, err := localKMS.ExportPubKeyBytes(kid)
			if err != nil {
				return nil, fmt.Errorf("failed to export public key[%s] from kms: %s", kid, err.Error())
			}

			return &verifier.PublicKey{
				Type:  kms.ED25519,
				Value: pubKeyBytes,
			}, nil
		},
		DocLoader: orbDocumentLoader,
	}

	anchorGraph := graph.New(graphProviders)

	// get protocol client provider
	pcp, err := getProtocolClientProvider(parameters, casClient, opStore, anchorGraph)
	if err != nil {
		return fmt.Errorf("failed to create protocol client provider: %s", err.Error())
	}

	pc, err := pcp.ForNamespace(parameters.didNamespace)
	if err != nil {
		return fmt.Errorf("failed to get protocol client for namespace [%s]: %s", parameters.didNamespace, err.Error())
	}

	// TODO: For now create key at startup, we need different way of handling this key as orb parameter
	// once we figure out how to expose verification method (webfinger, did:web)
	keyID, _, err := localKMS.Create(kms.ED25519Type)
	if err != nil {
		return fmt.Errorf("failed to create anchor credential signing key: %s", err.Error())
	}

	signingParams := vcsigner.SigningParams{
		VerificationMethod: "did:web:abc#" + keyID,
		Domain:             parameters.anchorCredentialParams.domain,
		SignatureSuite:     parameters.anchorCredentialParams.signatureSuite,
	}

	signingProviders := &vcsigner.Providers{
		KeyManager: localKMS,
		Crypto:     crypto,
		DocLoader:  orbDocumentLoader,
	}

	vcSigner, err := vcsigner.New(signingProviders, signingParams)
	if err != nil {
		return fmt.Errorf("failed to create vc signer: %s", err.Error())
	}

	vcBuilderParams := builder.Params{
		Issuer: parameters.anchorCredentialParams.issuer,
		URL:    parameters.anchorCredentialParams.url,
	}

	vcBuilder, err := builder.New(vcSigner, vcBuilderParams)
	if err != nil {
		return fmt.Errorf("failed to create vc builder: %s", err.Error())
	}

	// create anchor channel (used by anchor writer to notify observer about anchors)
	anchorCh := make(chan []string, chBuffer)

	// create did channel (used by resolver to notify observer about "not-found" DIDs)
	didCh := make(chan []string, chBuffer)

	// used to notify anchor writer about witnessed anchor credential
	vcCh := make(chan *verifiable.Credential, chBuffer)

	vcStore, err := vcstore.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create vc store: %s", err.Error())
	}

	opProcessor := processor.New(parameters.didNamespace, opStore, pc)

	casIRI, err := url.Parse(fmt.Sprintf("%s%s", parameters.externalEndpoint, casPath))
	if err != nil {
		return fmt.Errorf("invalid CAS service IRI: %s", err.Error())
	}

	apServiceIRI, err := url.Parse(fmt.Sprintf("%s%s", parameters.externalEndpoint, activityPubServicesPath))
	if err != nil {
		return fmt.Errorf("invalid service IRI: %s", err.Error())
	}

	apTransactionsIRI, err := url.Parse(fmt.Sprintf("%s%s", parameters.externalEndpoint, activityPubTransactionsPath))
	if err != nil {
		return fmt.Errorf("invalid transactions IRI: %s", err.Error())
	}

	apConfig := &apservice.Config{
		ServiceEndpoint: activityPubServicesPath,
		ServiceIRI:      apServiceIRI,
		MaxWitnessDelay: defaultMaxWitnessDelay,
	}

	apStore := apmemstore.New(apConfig.ServiceEndpoint)

	// TODO: Configure the HTTP client with TLS
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint: gosec
			},
		},
	}

	activityPubService, err := apservice.New(apConfig,
		apStore, httpClient,
		// TODO: Define all of the ActivityPub handlers
		// apspi.WithProofHandler(proofHandler),
		apspi.WithWitness(vct.New(parameters.vctURL, vct.WithHTTPClient(httpClient))),
		// apspi.WithFollowerAuth(followerAuth),
		apspi.WithAnchorCredentialHandler(handler.New(anchorCh)),
		// apspi.WithUndeliverableHandler(undeliverableHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	proofProviders := &proofs.Providers{
		DocLoader: orbDocumentLoader,
	}

	proofHandler := proofs.New(proofProviders, vcCh, apServiceIRI)

	anchorWriterProviders := &writer.Providers{
		AnchorGraph:   anchorGraph,
		DidAnchors:    didAnchors,
		AnchorBuilder: vcBuilder,
		Store:         vcStore,
		ProofHandler:  proofHandler,
		OpProcessor:   opProcessor,
		Outbox:        activityPubService.Outbox(),
	}

	anchorWriter := writer.New(parameters.didNamespace, apServiceIRI, casIRI, anchorWriterProviders, anchorCh, vcCh)

	// create new batch writer
	batchWriter, err := batch.New(parameters.didNamespace,
		sidetreecontext.New(pc, anchorWriter),
		batch.WithBatchTimeout(parameters.batchWriterTimeout))
	if err != nil {
		return fmt.Errorf("failed to create batch writer: %s", err.Error())
	}

	// start routine for creating batches
	batchWriter.Start()
	logger.Infof("started batch writer")

	// create new observer and start it
	providers := &observer.Providers{
		TxnProvider:            mockTxnProvider{registerForAnchor: anchorCh, registerForDID: didCh},
		ProtocolClientProvider: pcp,
		AnchorGraph:            anchorGraph,
	}

	observer.New(providers).Start()
	logger.Infof("started observer")

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		opProcessor,
	)

	apServiceCfg := &aphandler.Config{
		BasePath:  activityPubServicesPath,
		ObjectIRI: apServiceIRI,
		PageSize:  100, // TODO: Make configurable
	}

	apTxnCfg := &aphandler.Config{
		BasePath:  activityPubTransactionsPath,
		ObjectIRI: apTransactionsIRI,
		PageSize:  100, // TODO: Make configurable
	}

	// FIXME: Configure with real values.
	publicKey := &vocab.PublicKeyType{
		ID:           apServiceIRI.String() + "#main-key",
		Owner:        apServiceIRI.String(),
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki.....",
	}

	orbResolver := resolver.NewResolveHandler(
		parameters.didNamespace,
		parameters.didAliases,
		didDocHandler,
		localdiscovery.New(didCh),
	)

	// create discovery rest api
	endpointDiscoveryOp := discoveryrest.New(&discoveryrest.Config{
		ResolutionPath:            baseResolvePath,
		OperationPath:             baseUpdatePath,
		BaseURL:                   parameters.externalEndpoint,
		DiscoveryDomains:          parameters.discoveryDomains,
		DiscoveryMinimumResolvers: parameters.discoveryMinimumResolvers,
	})

	handlers := make([]restcommon.HTTPHandler, 0)

	handlers = append(handlers, diddochandler.NewUpdateHandler(baseUpdatePath, didDocHandler, pc),
		diddochandler.NewResolveHandler(baseResolvePath, orbResolver),
		activityPubService.InboxHTTPHandler(),
		aphandler.NewServices(apServiceCfg, apStore, publicKey),
		aphandler.NewFollowers(apServiceCfg, apStore),
		aphandler.NewFollowing(apServiceCfg, apStore),
		aphandler.NewOutbox(apServiceCfg, apStore),
		aphandler.NewInbox(apServiceCfg, apStore),
		aphandler.NewWitnesses(apServiceCfg, apStore),
		aphandler.NewWitnessing(apServiceCfg, apStore),
		aphandler.NewLiked(apServiceCfg, apStore),
		aphandler.NewLikes(apTxnCfg, apStore),
		aphandler.NewShares(apTxnCfg, apStore))

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		parameters.token,
		handlers...,
	)

	srv := &HTTPServer{
		activityPubService: activityPubService,
	}

	return srv.Start(httpServer)
}

// pre-load orb contexts for vc, anchor, jws.
func loadOrbContexts() (*jld.CachingDocumentLoader, error) {
	docLoader := verifiable.CachingJSONLDLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(builder.AnchorContextV1))
	if err != nil {
		return nil, fmt.Errorf("failed to preload anchor credential jsonld context: %w", err)
	}

	docLoader.AddDocument(
		builder.AnchorContextURIV1,
		reader,
	)

	reader, err = ld.DocumentFromReader(strings.NewReader(builder.JwsContextV1))
	if err != nil {
		return nil, fmt.Errorf("failed to preload jws jsonld context: %w", err)
	}

	docLoader.AddDocument(
		builder.JwsContextURIV1,
		reader,
	)

	return docLoader, nil
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, opStore common.OperationStore, anchorGraph common.AnchorGraph) (*orbpcp.ClientProvider, error) {
	versions := []string{"1.0"}

	sidetreeCfg := config.Sidetree{
		MethodContext: parameters.methodContext,
		EnableBase:    parameters.baseEnabled,
		AnchorOrigins: parameters.allowedOrigins,
	}

	registry := factoryregistry.New()

	var protocolVersions []protocol.Version
	for _, version := range versions {
		pv, err := registry.CreateProtocolVersion(version, casClient, opStore, anchorGraph, sidetreeCfg)
		if err != nil {
			return nil, fmt.Errorf("error creating protocol version [%s]: %s", version, err)
		}

		protocolVersions = append(protocolVersions, pv)
	}

	pcp := orbpcp.New()
	pcp.Add(parameters.didNamespace, orbpc.New(protocolVersions))

	return pcp, nil
}

type kmsProvider struct {
	storageProvider   ariesstorage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

type storageProviders struct {
	provider           ariesstorage.Provider
	kmsSecretsProvider ariesstorage.Provider
}

//nolint: gocyclo
func createStoreProviders(parameters *orbParameters) (*storageProviders, error) {
	var edgeServiceProvs storageProviders

	switch { //nolint: dupl
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		edgeServiceProvs.provider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		var err error

		edgeServiceProvs.provider, err =
			ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMYSQLDBOption):
		var err error

		edgeServiceProvs.provider, err =
			ariesmysqlstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}
	default:
		return &storageProviders{}, fmt.Errorf("database type not set to a valid type." +
			" run start --help to see the available options")
	}

	switch { //nolint: dupl
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMemOption):
		edgeServiceProvs.kmsSecretsProvider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeCouchDBOption):
		var err error

		edgeServiceProvs.kmsSecretsProvider, err =
			ariescouchdbstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMYSQLDBOption):
		var err error

		edgeServiceProvs.kmsSecretsProvider, err =
			ariesmysqlstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
				ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}
	default:
		return &storageProviders{}, fmt.Errorf("key database type not set to a valid type." +
			" run start --help to see the available options")
	}

	return &edgeServiceProvs, nil
}

func createKMS(kmsSecretsProvider ariesstorage.Provider) (*localkms.LocalKMS, error) {
	localKMS, err := createLocalKMS(kmsSecretsProvider)
	if err != nil {
		return nil, err
	}

	return localKMS, nil
}

func createLocalKMS(kmsSecretsStoreProvider ariesstorage.Provider) (*localkms.LocalKMS, error) {
	masterKeyReader, err := prepareMasterKeyReader(kmsSecretsStoreProvider)
	if err != nil {
		return nil, err
	}

	secretLockService, err := local.NewService(masterKeyReader, nil)
	if err != nil {
		return nil, err
	}

	kmsProv := kmsProvider{
		storageProvider:   kmsSecretsStoreProvider,
		secretLockService: secretLockService,
	}

	return localkms.New(masterKeyURI, kmsProv)
}

// prepareMasterKeyReader prepares a master key reader for secret lock usage
func prepareMasterKeyReader(kmsSecretsStoreProvider ariesstorage.Provider) (*bytes.Reader, error) {
	masterKeyStore, err := kmsSecretsStoreProvider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			logger.Infof("master key[%s] not found, creating new one ...", masterKeyDBKeyName)

			masterKeyRaw := random.GetRandomBytes(uint32(masterKeyNumBytes))
			masterKey = []byte(base64.URLEncoding.EncodeToString(masterKeyRaw))

			putErr := masterKeyStore.Put(masterKeyDBKeyName, masterKey)
			if putErr != nil {
				return nil, putErr
			}
		} else {
			return nil, err
		}
	}

	masterKeyReader := bytes.NewReader(masterKey)

	return masterKeyReader, nil
}

type mockTxnProvider struct {
	registerForAnchor chan []string
	registerForDID    chan []string
}

func (m mockTxnProvider) RegisterForAnchor() <-chan []string {
	return m.registerForAnchor
}

func (m mockTxnProvider) RegisterForDID() <-chan []string {
	return m.registerForDID
}
