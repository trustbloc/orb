/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmysqlstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	acrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrweb "github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/httpsig"
	aphandler "github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apservice "github.com/trustbloc/orb/pkg/activitypub/service"
	"github.com/trustbloc/orb/pkg/activitypub/service/monitoring"
	apspi "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	apariesstore "github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	apmemstore "github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	activitypubspi "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/handler/credential"
	"github.com/trustbloc/orb/pkg/anchor/handler/proof"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/policy"
	"github.com/trustbloc/orb/pkg/anchor/writer"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	ipfscas "github.com/trustbloc/orb/pkg/cas/ipfs"
	"github.com/trustbloc/orb/pkg/cas/resolver"
	orbcaswriter "github.com/trustbloc/orb/pkg/cas/writer"
	"github.com/trustbloc/orb/pkg/config"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	"github.com/trustbloc/orb/pkg/context/common"
	orbpc "github.com/trustbloc/orb/pkg/context/protocol/client"
	orbpcp "github.com/trustbloc/orb/pkg/context/protocol/provider"
	localdiscovery "github.com/trustbloc/orb/pkg/discovery/did/local"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/ldcontextrest"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/protocolversion/factoryregistry"
	"github.com/trustbloc/orb/pkg/pubsub/amqp"
	"github.com/trustbloc/orb/pkg/resolver/document"
	casstore "github.com/trustbloc/orb/pkg/store/cas"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	"github.com/trustbloc/orb/pkg/store/operation"
	"github.com/trustbloc/orb/pkg/store/vcstatus"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
	proofstore "github.com/trustbloc/orb/pkg/store/witness"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/webcas"
)

const (
	masterKeyURI = "local-lock://custom/master/key/"

	chBuffer = 100

	defaultMaxWitnessDelay = 600 * time.Second // 10 minutes

	noStartupDelay = 0 * time.Second // no delay

	defaulthttpSignaturesEnabled = true

	unpublishedDIDLabel = "interim"

	defaultPolicyCacheExpiry = 30 * time.Second
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/v1"

	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"

	activityPubServicesPath     = "/services/orb"
	activityPubTransactionsPath = "/transactions"

	casPath = "/cas"

	kmsKeyType             = kms.ED25519Type
	verificationMethodType = "Ed25519VerificationKey2018"

	webKeyStoreKey = "web-key-store"
	kidKey         = "kid"
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

// BuildKMSURL builds kms URL.
func BuildKMSURL(base, uri string) string {
	if strings.HasPrefix(uri, "/") {
		return base + uri
	}

	return uri
}

func createKMSAndCrypto(parameters *orbParameters, client *http.Client,
	store storage.Provider, cfg storage.Store) (kms.KeyManager, acrypto.Crypto, error) {
	if parameters.kmsEndpoint != "" || parameters.kmsStoreEndpoint != "" {
		if parameters.kmsStoreEndpoint != "" {
			return webkms.New(parameters.kmsStoreEndpoint, client), webcrypto.New(parameters.kmsStoreEndpoint, client), nil
		}

		var keystoreURL string

		err := getOrInit(cfg, webKeyStoreKey, &keystoreURL, func() (interface{}, error) {
			location, _, err := webkms.CreateKeyStore(client, parameters.kmsEndpoint, uuid.New().String(), "")

			return location, err
		})
		if err != nil {
			return nil, nil, fmt.Errorf("get or init: %w", err)
		}

		keystoreURL = BuildKMSURL(parameters.kmsEndpoint, keystoreURL)
		parameters.kmsStoreEndpoint = keystoreURL

		return webkms.New(keystoreURL, client), webcrypto.New(keystoreURL, client), nil
	}

	secretLockService, err := prepareKeyLock(parameters.secretLockKeyPath)
	if err != nil {
		return nil, nil, err
	}

	km, err := localkms.New(masterKeyURI, &kmsProvider{
		storageProvider:   store,
		secretLockService: secretLockService,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create kms: %w", err)
	}

	cr, err := tinkcrypto.New()
	if err != nil {
		return nil, nil, fmt.Errorf("create crypto: %w", err)
	}

	return km, cr, nil
}

func createKID(km kms.KeyManager, parameters *orbParameters, cfg storage.Store) error {
	return getOrInit(cfg, kidKey, &parameters.keyID, func() (interface{}, error) {
		keyID, _, err := km.Create(kmsKeyType)

		return keyID, err
	})
}

// nolint: gocyclo,funlen,gocognit
func startOrbServices(parameters *orbParameters) error {
	if parameters.logLevel != "" {
		SetDefaultLogLevel(logger, parameters.logLevel)
	}

	if parameters.startupDelay != noStartupDelay {
		logger.Infof("delaying server start-up for duration: %s", parameters.startupDelay)
		time.Sleep(parameters.startupDelay)
	}

	storeProviders, err := createStoreProviders(parameters)
	if err != nil {
		return err
	}

	configStore, err := storeProviders.provider.OpenStore("orb-config")
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	// TODO: Configure the HTTP client with TLS
	httpClient := &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint: gosec
			},
		},
	}

	km, cr, err := createKMSAndCrypto(parameters, httpClient, storeProviders.kmsSecretsProvider, configStore)
	if err != nil {
		return err
	}

	var coreCasClient extendedcasclient.Client
	var anchorCasWriter *orbcaswriter.CasWriter

	switch parameters.casType {
	case "ipfs":
		coreCasClient = ipfscas.New(parameters.ipfsURL, extendedcasclient.WithCIDVersion(parameters.cidVersion))
		anchorCasWriter = orbcaswriter.New(coreCasClient, "ipfs")
	case "local":
		var err error

		coreCasClient, err = casstore.New(storeProviders.provider,
			extendedcasclient.WithCIDVersion(parameters.cidVersion))
		if err != nil {
			return err
		}

		u, err := url.Parse(parameters.externalEndpoint)
		if err != nil {
			return fmt.Errorf("failed to parse external endpoint: %s", err.Error())
		}

		anchorCasWriter = orbcaswriter.New(coreCasClient, "webcas:"+u.Host)
	}

	didAnchors, err := didanchorstore.New(storeProviders.provider)
	if err != nil {
		return err
	}

	opStore, err := operation.New(storeProviders.provider)
	if err != nil {
		return err
	}

	// NOTE: Changing this storage requires changing storage for 'ldcontextrest.New' as well.
	orbDocumentLoader, err := jld.NewDocumentLoader(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to load Orb contexts: %s", err.Error())
	}

	vdr := vdr.New(
		vdr.WithVDR(&webVDR{http: httpClient, VDR: vdrweb.New()}),
	)

	if parameters.keyID == "" {
		if err = createKID(km, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	apServicePublicKeyIRI := mustParseURL(parameters.externalEndpoint,
		fmt.Sprintf("%s/keys/%s", activityPubServicesPath, aphandler.MainKeyID))

	apGetSigner, apPostSigner := getActivityPubSigners(parameters, km, cr)

	t := transport.New(httpClient, apServicePublicKeyIRI, apGetSigner, apPostSigner)

	var ipfsReader *ipfscas.Client
	if parameters.ipfsURL != "" {
		ipfsReader = ipfscas.New(parameters.ipfsURL, extendedcasclient.WithCIDVersion(parameters.cidVersion))
	}

	casResolver := resolver.New(coreCasClient, ipfsReader, t)

	graphProviders := &graph.Providers{
		CasResolver: casResolver,
		CasWriter:   anchorCasWriter,
		Pkf:         verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher(),
		DocLoader:   orbDocumentLoader,
	}

	anchorGraph := graph.New(graphProviders)

	// get protocol client provider
	pcp, err := getProtocolClientProvider(parameters, coreCasClient, casResolver, opStore, anchorGraph)
	if err != nil {
		return fmt.Errorf("failed to create protocol client provider: %s", err.Error())
	}

	pc, err := pcp.ForNamespace(parameters.didNamespace)
	if err != nil {
		return fmt.Errorf("failed to get protocol client for namespace [%s]: %s", parameters.didNamespace, err.Error())
	}

	u, err := url.Parse(parameters.externalEndpoint)
	if err != nil {
		return fmt.Errorf("parse external endpoint: %w", err)
	}

	signingParams := vcsigner.SigningParams{
		VerificationMethod: "did:web:" + u.Host + "#" + parameters.keyID,
		Domain:             parameters.anchorCredentialParams.domain,
		SignatureSuite:     parameters.anchorCredentialParams.signatureSuite,
	}

	signingProviders := &vcsigner.Providers{
		KeyManager: km,
		Crypto:     cr,
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

	vcBuilder, err := builder.New(vcBuilderParams)
	if err != nil {
		return fmt.Errorf("failed to create vc builder: %s", err.Error())
	}

	// create anchor channel (used by anchor writer to notify observer about anchors)
	anchorCh := make(chan []anchorinfo.AnchorInfo, chBuffer)

	// create did channel (used by resolver to notify observer about "not-found" DIDs)
	didCh := make(chan []string, chBuffer)

	// used to notify anchor writer about witnessed anchor credential
	vcCh := make(chan *verifiable.Credential, chBuffer)

	vcStore, err := vcstore.New(storeProviders.provider, orbDocumentLoader)
	if err != nil {
		return fmt.Errorf("failed to create vc store: %s", err.Error())
	}

	witnessProofStore, err := proofstore.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create proof store: %s", err.Error())
	}

	vcStatusStore, err := vcstatus.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create vc status store: %s", err.Error())
	}

	opProcessor := processor.New(parameters.didNamespace, opStore, pc)

	casIRI := mustParseURL(parameters.externalEndpoint, casPath)

	apServiceIRI := mustParseURL(parameters.externalEndpoint, activityPubServicesPath)

	apTransactionsIRI := mustParseURL(parameters.externalEndpoint, activityPubTransactionsPath)

	apConfig := &apservice.Config{
		ServiceEndpoint:        activityPubServicesPath,
		ServiceIRI:             apServiceIRI,
		MaxWitnessDelay:        parameters.maxWitnessDelay,
		VerifyActorInSignature: parameters.httpSignaturesEnabled,
	}

	if parameters.mqURL != "" {
		apConfig.PubSubFactory = func(serviceName string) apservice.PubSub {
			logger.Infof("[%s] Creating new AMQP publisher/subscriber at URL [%s]", serviceName, parameters.mqURL)

			return amqp.New(serviceName, amqp.Config{URI: parameters.mqURL})
		}
	}

	var apStore activitypubspi.Store

	if parameters.dbParameters.databaseType == databaseTypeCouchDBOption {
		couchDBProvider, err := ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix+"_"+apConfig.ServiceEndpoint),
			ariescouchdbstorage.WithLogger(logger))
		if err != nil {
			return fmt.Errorf("failed to create CouchDB storage provider for ActivityPub: %w", err)
		}

		apStore, err = apariesstore.New(couchDBProvider, apConfig.ServiceEndpoint)
		if err != nil {
			return fmt.Errorf("failed to create in-memory storage provider for ActivityPub: %w", err)
		}
	} else {
		apStore = apmemstore.New(apConfig.ServiceEndpoint)
	}

	pubKey, err := km.ExportPubKeyBytes(parameters.keyID)
	if err != nil {
		return fmt.Errorf("failed to export pub key: %w", err)
	}

	publicKey, err := getActivityPubPublicKey(pubKey, apServiceIRI, apServicePublicKeyIRI)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	apSigVerifier := getActivityPubVerifier(parameters, km, cr, t)

	monitoringSvc, err := monitoring.New(storeProviders.provider, orbDocumentLoader, monitoring.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("monitoring: %w", err)
	}

	defer monitoringSvc.Close()

	witnessPolicy, err := policy.New(configStore, defaultPolicyCacheExpiry)
	if err != nil {
		return fmt.Errorf("failed to create witness policy: %s", err.Error())
	}

	proofHandler := proof.New(
		&proof.Providers{
			VCStore:       vcStore,
			VCStatusStore: vcStatusStore,
			MonitoringSvc: monitoringSvc,
			DocLoader:     orbDocumentLoader,
			WitnessStore:  witnessProofStore,
			WitnessPolicy: witnessPolicy,
		},
		vcCh)

	var witness apspi.WitnessHandler = vct.NewNoOpClient()

	if parameters.vctURL != "" {
		witness = vct.New(parameters.vctURL, vcSigner,
			vct.WithHTTPClient(httpClient),
			vct.WithDocumentLoader(orbDocumentLoader))
	}

	activityPubService, err := apservice.New(apConfig,
		apStore, t, apSigVerifier,
		apspi.WithProofHandler(proofHandler),
		apspi.WithWitness(witness),
		apspi.WithAnchorCredentialHandler(credential.New(
			anchorCh, casResolver, orbDocumentLoader, monitoringSvc, parameters.maxWitnessDelay,
		)),
		// TODO: Define the following ActivityPub handlers.
		// apspi.WithWitnessInvitationAuth(inviteWitnessAuth),
		// apspi.WithFollowerAuth(followerAuth),
		// apspi.WithUndeliverableHandler(undeliverableHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	anchorWriterProviders := &writer.Providers{
		AnchorGraph:   anchorGraph,
		DidAnchors:    didAnchors,
		AnchorBuilder: vcBuilder,
		VCStore:       vcStore,
		VCStatusStore: vcStatusStore,
		OpProcessor:   opProcessor,
		Outbox:        activityPubService.Outbox(),
		Witness:       witness,
		Signer:        vcSigner,
		MonitoringSvc: monitoringSvc,
		ActivityStore: apStore,
		WitnessStore:  witnessProofStore,
	}

	anchorWriter := writer.New(parameters.didNamespace,
		apServiceIRI, casIRI,
		anchorWriterProviders,
		anchorCh, vcCh,
		parameters.maxWitnessDelay,
		parameters.signWithLocalWitness)

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
		DidAnchors:             didAnchors,
	}

	observer.New(providers).Start()
	logger.Infof("started observer")

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		opProcessor,
		dochandler.WithDomain(u.Host),
		dochandler.WithLabel(unpublishedDIDLabel),
	)

	authCfg := auth.Config{
		AuthTokensDef: parameters.authTokenDefinitions,
		AuthTokens:    parameters.authTokens,
	}

	apEndpointCfg := &aphandler.Config{
		Config:                 authCfg,
		BasePath:               activityPubServicesPath,
		ObjectIRI:              apServiceIRI,
		VerifyActorInSignature: parameters.httpSignaturesEnabled,
		PageSize:               100, // TODO: Make configurable
	}

	apTxnEndpointCfg := &aphandler.Config{
		Config:    authCfg,
		BasePath:  activityPubTransactionsPath,
		ObjectIRI: apTransactionsIRI,
		PageSize:  100, // TODO: Make configurable
	}

	orbResolver := document.NewResolveHandler(
		parameters.didNamespace,
		parameters.didAliases,
		unpublishedDIDLabel,
		didDocHandler,
		localdiscovery.New(didCh),
	)

	// create discovery rest api
	endpointDiscoveryOp, err := discoveryrest.New(&discoveryrest.Config{
		PubKey:                    pubKey,
		VerificationMethodType:    verificationMethodType,
		KID:                       parameters.keyID,
		ResolutionPath:            baseResolvePath,
		OperationPath:             baseUpdatePath,
		WebCASPath:                casPath,
		BaseURL:                   parameters.externalEndpoint,
		DiscoveryDomains:          parameters.discoveryDomains,
		DiscoveryMinimumResolvers: parameters.discoveryMinimumResolvers,
		VctURL:                    parameters.vctURL,
		DiscoveryVctDomains:       parameters.discoveryVctDomains,
	})
	if err != nil {
		return fmt.Errorf("discovery rest: %w", err)
	}

	// NOTE: We are using the same storage as we use for ld document loader.
	// Changing this storage requires changing storage for ld document loader as well.
	ctxRest, err := ldcontextrest.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("ldcontext rest: %w", err)
	}

	handlers := make([]restcommon.HTTPHandler, 0)

	handlers = append(handlers,
		auth.NewHandlerWrapper(authCfg, diddochandler.NewUpdateHandler(baseUpdatePath, didDocHandler, pc)),
		auth.NewHandlerWrapper(authCfg, diddochandler.NewResolveHandler(baseResolvePath, orbResolver)),
		activityPubService.InboxHTTPHandler(),
		aphandler.NewServices(apEndpointCfg, apStore, publicKey),
		aphandler.NewPublicKeys(apEndpointCfg, apStore, publicKey),
		aphandler.NewFollowers(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewFollowing(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewOutbox(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewInbox(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewWitnesses(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewWitnessing(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewLiked(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewLikes(apTxnEndpointCfg, apStore, apSigVerifier),
		aphandler.NewShares(apTxnEndpointCfg, apStore, apSigVerifier),
		aphandler.NewPostOutbox(apEndpointCfg, activityPubService.Outbox(), apStore, apSigVerifier),
		aphandler.NewActivity(apEndpointCfg, apStore, apSigVerifier),
		webcas.New(apEndpointCfg, apStore, apSigVerifier, coreCasClient),
		ctxRest,
	)

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		handlers...,
	)

	srv := &HTTPServer{
		activityPubService: activityPubService,
	}

	return srv.Start(httpServer)
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, casResolver common.CASResolver, opStore common.OperationStore, anchorGraph common.AnchorGraph) (*orbpcp.ClientProvider, error) {
	versions := []string{"1.0"}

	sidetreeCfg := config.Sidetree{
		MethodContext: parameters.methodContext,
		EnableBase:    parameters.baseEnabled,
		AnchorOrigins: parameters.allowedOrigins,
	}

	registry := factoryregistry.New()

	var protocolVersions []protocol.Version
	for _, version := range versions {
		pv, err := registry.CreateProtocolVersion(version, casClient, casResolver, opStore, anchorGraph, sidetreeCfg)
		if err != nil {
			return nil, fmt.Errorf("error creating protocol version [%s]: %s", version, err)
		}

		protocolVersions = append(protocolVersions, pv)
	}

	pcp := orbpcp.New()
	pcp.Add(parameters.didNamespace, orbpc.New(protocolVersions))

	return pcp, nil
}

type webVDR struct {
	http *http.Client
	*vdrweb.VDR
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return w.VDR.Read(didID, append(opts, vdrapi.WithOption(vdrweb.HTTPClientOpt, w.http))...)
}

type kmsProvider struct {
	storageProvider   storage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

type storageProviders struct {
	provider           storage.Provider
	kmsSecretsProvider storage.Provider
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

	if parameters.kmsStoreEndpoint != "" || parameters.kmsEndpoint != "" {
		return &edgeServiceProvs, nil
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

func getOrInit(cfg storage.Store, key string, v interface{}, initFn func() (interface{}, error)) error {
	src, err := cfg.Get(key)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get config value for %q: %w", key, err)
	}

	if err == nil {
		return json.Unmarshal(src, v)
	}

	val, err := initFn()
	if err != nil {
		return fmt.Errorf("init config value for %q: %w", key, err)
	}

	src, err = json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal config value for %q: %w", key, err)
	}

	if err = cfg.Put(key, src); err != nil {
		return fmt.Errorf("marshal config value for %q: %w", key, err)
	}

	return getOrInit(cfg, key, v, initFn)
}

// prepareKeyLock prepares a key lock usage.
func prepareKeyLock(keyPath string) (secretlock.Service, error) {
	if keyPath == "" {
		return &noop.NoLock{}, nil
	}

	masterKeyReader, err := local.MasterKeyFromPath(keyPath)
	if err != nil {
		return nil, err
	}

	return local.NewService(masterKeyReader, nil)
}

type mockTxnProvider struct {
	registerForAnchor chan []anchorinfo.AnchorInfo
	registerForDID    chan []string
}

func (m mockTxnProvider) RegisterForAnchor() <-chan []anchorinfo.AnchorInfo {
	return m.registerForAnchor
}

func (m mockTxnProvider) RegisterForDID() <-chan []string {
	return m.registerForDID
}

func mustParseURL(basePath, relativePath string) *url.URL {
	u, err := url.Parse(fmt.Sprintf("%s%s", basePath, relativePath))
	if err != nil {
		panic(fmt.Errorf("invalid URL: %s", err.Error()))
	}

	return u
}

func getActivityPubPublicKey(pubKey []byte, apServiceIRI, apServicePublicKeyIRI *url.URL) (*vocab.PublicKeyType, error) {
	pubDerKey, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pubKey))
	if err != nil {
		return nil, fmt.Errorf("marshal pub key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDerKey,
	})

	return vocab.NewPublicKey(
		vocab.WithID(apServicePublicKeyIRI),
		vocab.WithOwner(apServiceIRI),
		vocab.WithPublicKeyPem(string(pemBytes)),
	), nil
}

type signer interface {
	SignRequest(pubKeyID string, req *http.Request) error
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

func getActivityPubSigners(parameters *orbParameters, km kms.KeyManager,
	cr acrypto.Crypto) (getSigner signer, postSigner signer) {
	if parameters.httpSignaturesEnabled {
		getSigner = httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), cr, km, parameters.keyID)
		postSigner = httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), cr, km, parameters.keyID)
	} else {
		getSigner = &transport.NoOpSigner{}
		postSigner = &transport.NoOpSigner{}
	}

	return
}

type httpTransport interface {
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

func getActivityPubVerifier(parameters *orbParameters, km kms.KeyManager,
	cr acrypto.Crypto, t httpTransport) signatureVerifier {
	if parameters.httpSignaturesEnabled {
		return httpsig.NewVerifier(client.New(t), cr, km)
	}

	logger.Warnf("HTTP signature verification for ActivityPub is disabled.")

	return &noOpVerifier{}
}

type noOpVerifier struct {
}

func (v *noOpVerifier) VerifyRequest(req *http.Request) (bool, *url.URL, error) {
	return true, nil, nil
}
