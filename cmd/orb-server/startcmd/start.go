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
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/tink/go/subtle/random"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmysqlstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"

	"github.com/trustbloc/orb/pkg/context/cas"
	"github.com/trustbloc/orb/pkg/context/txnclient"
	"github.com/trustbloc/orb/pkg/didtxnref/memdidtxnref"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/mocks"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/txngraph"
	"github.com/trustbloc/orb/pkg/txnprocessor"
	"github.com/trustbloc/orb/pkg/vcbuilder"
	"github.com/trustbloc/orb/pkg/vcsigner"
)

const (
	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	masterKeyNumBytes = 32

	txnBuffer = 100
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/0.0.1"
)

type server interface {
	Start(srv *httpserver.Server) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct {
}

// Start starts the http server
func (s *HTTPServer) Start(srv *httpserver.Server) error {
	if err := srv.Start(); err != nil {
		return err
	}

	logger.Infof("started orb rest service")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	return nil

}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start orb-server",
		Long:  "Start orb-server",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getOrbParameters(cmd)
			if err != nil {
				return err
			}

			return startOrbServices(parameters, srv)
		},
	}
}

// nolint: gocyclo,funlen,gocognit
func startOrbServices(parameters *orbParameters, srv server) error {
	if parameters.logLevel != "" {
		SetDefaultLogLevel(logger, parameters.logLevel)
	}

	edgeServiceProvs, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	localKMS, err := createKMS(edgeServiceProvs.kmsSecretsProvider)
	if err != nil {
		return err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return err
	}

	// basic providers (CAS + operation store)
	casClient := cas.New(parameters.casURL)
	opStore := mocks.NewMockOperationStore()

	// TODO: For now fetch signing public key from local KMS (this will handled differently later on: webfinger or did:web)
	txnGraph := txngraph.New(casClient, func(_, keyID string) (*verifier.PublicKey, error) {
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

	vcBuilder, err := vcbuilder.New(vcSigner, vcbuilder.BuilderParams{Issuer: parameters.anchorCredentialParams.issuer})
	if err != nil {
		return fmt.Errorf("failed to create vc builder: %s", err.Error())
	}

	// create transaction channel (used by transaction client to notify observer about orb transactions)
	sidetreeTxnCh := make(chan []string, txnBuffer)
	txnClient := getTransactionClient(vcBuilder, txnGraph, sidetreeTxnCh)

	// create new batch writer
	batchWriter, err := batch.New(parameters.didNamespace, sidetreecontext.New(pc, txnClient))
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

	// did document handler with did document validator for didDocNamespace
	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		processor.New(parameters.didNamespace, opStore, pc),
	)

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		parameters.token,
		diddochandler.NewUpdateHandler(basePath, didDocHandler, pc),
		diddochandler.NewResolveHandler(basePath, didDocHandler),
	)

	return srv.Start(httpServer)
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, opStore txnprocessor.OperationStore, graph *txngraph.Graph) *mocks.MockProtocolClientProvider {
	return mocks.NewMockProtocolClientProvider().
		WithOpStore(opStore).
		WithOpStoreClient(opStore).
		WithMethodContext(parameters.methodContext).
		WithBase(parameters.baseEnabled).
		WithCasClient(casClient).
		WithTxnGraph(graph)
}

func getTransactionClient(builder *vcbuilder.Builder, txnGraph *txngraph.Graph, sidetreeTxnCh chan []string) batch.BlockchainClient {
	txnClientProviders := &txnclient.Providers{TxnGraph: txnGraph, DidTxns: memdidtxnref.New(), TxnBuilder: builder}
	txnClient := txnclient.New("did:sidetree", txnClientProviders, sidetreeTxnCh)

	return txnClient
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

type edgeServiceProviders struct {
	provider           ariesstorage.Provider
	kmsSecretsProvider ariesstorage.Provider
}

//nolint: gocyclo
func createStoreProviders(parameters *orbParameters) (*edgeServiceProviders, error) {
	var edgeServiceProvs edgeServiceProviders

	switch { //nolint: dupl
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		edgeServiceProvs.provider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		var err error

		edgeServiceProvs.provider, err =
			ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return &edgeServiceProviders{}, err
		}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMYSQLDBOption):
		var err error

		edgeServiceProvs.provider, err =
			ariesmysqlstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.databasePrefix))
		if err != nil {
			return &edgeServiceProviders{}, err
		}
	default:
		return &edgeServiceProviders{}, fmt.Errorf("database type not set to a valid type." +
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
			return &edgeServiceProviders{}, err
		}
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMYSQLDBOption):
		var err error

		edgeServiceProvs.kmsSecretsProvider, err =
			ariesmysqlstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
				ariesmysqlstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))
		if err != nil {
			return &edgeServiceProviders{}, err
		}
	default:
		return &edgeServiceProviders{}, fmt.Errorf("key database type not set to a valid type." +
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
