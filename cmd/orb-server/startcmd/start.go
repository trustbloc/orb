/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"

	apservice "github.com/trustbloc/orb/pkg/activitypub/service"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/writer"
	"github.com/trustbloc/orb/pkg/context/cas"
	"github.com/trustbloc/orb/pkg/didtxnref/memdidtxnref"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/store/verifiable"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/versions/1_0/txnprocessor"
)

const (
	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	masterKeyNumBytes = 32

	txnBuffer = 100

	defaultMaxWitnessDelay = 10 * time.Minute
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/v1"

	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"

	activityPubServicePath = "/services/orb"
)

type server interface {
	Start(srv *httpserver.Server) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct {
	activityPubService service.ServiceLifecycle
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

	didTxns := memdidtxnref.New()
	opStore := mocks.NewMockOperationStore()

	// TODO: For now fetch signing public key from local KMS (this will handled differently later on: webfinger or did:web)
	txnGraph := graph.New(casClient, func(_, keyID string) (*verifier.PublicKey, error) {
		pubKeyBytes, err := localKMS.ExportPubKeyBytes(keyID[1:])
		if err != nil {
			return nil, fmt.Errorf("failed to export public key[%s] from kms: %s", keyID, err.Error())
		}

		return &verifier.PublicKey{
			Type:  kms.ED25519,
			Value: pubKeyBytes,
		}, nil
	})

	// get protocol client provider
	pcp := getProtocolClientProvider(parameters, casClient, opStore, txnGraph)
	pc, err := pcp.ForNamespace(mocks.DefaultNS)
	if err != nil {
		return fmt.Errorf("failed to get protocol client for namespace [%s]: %s", mocks.DefaultNS, err.Error())
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

	vcSigner, err := vcsigner.New(localKMS, crypto, signingParams)
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

	// create transaction channel (used by transaction client to notify observer about orb transactions)
	sidetreeTxnCh := make(chan []string, txnBuffer)

	vcStore, err := verifiable.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create vc store: %s", err.Error())
	}

	anchorWriterProviders := &writer.Providers{
		TxnGraph:   txnGraph,
		DidTxns:    didTxns,
		TxnBuilder: vcBuilder,
		Store:      vcStore,
	}

	anchorWriter := writer.New("did:sidetree", anchorWriterProviders, sidetreeTxnCh)

	// create new batch writer
	batchWriter, err := batch.New(parameters.didNamespace, sidetreecontext.New(pc, anchorWriter))
	if err != nil {
		return fmt.Errorf("failed to create batch writer: %s", err.Error())
	}

	// start routine for creating batches
	batchWriter.Start()
	logger.Infof("started batch writer")

	// create new observer and start it
	providers := &observer.Providers{
		TxnProvider:            mockTxnProvider{registerForSidetreeTxnValue: sidetreeTxnCh},
		ProtocolClientProvider: pcp,
		TxnGraph:               txnGraph,
	}

	observer.New(providers).Start()
	logger.Infof("started observer")

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		processor.New(parameters.didNamespace, opStore, pc),
	)

	apServiceIRI, err := url.Parse(fmt.Sprintf("https://%s%s", parameters.hostURL, activityPubServicePath))
	if err != nil {
		return fmt.Errorf("invalid service IRI: %s", err.Error())
	}

	apConfig := &apservice.Config{
		ServiceEndpoint: activityPubServicePath,
		ServiceIRI:      apServiceIRI,
		MaxWitnessDelay: defaultMaxWitnessDelay,
	}

	activityPubService, err := apservice.New(apConfig,
		memstore.New(apConfig.ServiceEndpoint),
		// TODO: Define all of the ActivityPub handlers
		//service.WithProofHandler(proofHandler),
		//service.WithWitness(witnessHandler),
		//service.WithFollowerAuth(followerAuth),
		//service.WithAnchorCredentialHandler(anchorCredHandler),
		//service.WithUndeliverableHandler(undeliverableHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		parameters.token,
		diddochandler.NewUpdateHandler(baseUpdatePath, didDocHandler, pc),
		diddochandler.NewResolveHandler(baseResolvePath, didDocHandler),
		activityPubService.InboxHTTPHandler(),
	)

	srv := &HTTPServer{
		activityPubService: activityPubService,
	}

	return srv.Start(httpServer)
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, opStore txnprocessor.OperationStore, graph *graph.Graph) *mocks.MockProtocolClientProvider {
	return mocks.NewMockProtocolClientProvider().
		WithOpStore(opStore).
		WithOpStoreClient(opStore).
		WithMethodContext(parameters.methodContext).
		WithBase(parameters.baseEnabled).
		WithCasClient(casClient).
		WithTxnGraph(graph).
		WithAllowedOrigins(parameters.allowedOrigins)
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
	registerForSidetreeTxnValue chan []string
}

func (m mockTxnProvider) RegisterForOrbTxn() <-chan []string {
	return m.registerForSidetreeTxnValue
}
