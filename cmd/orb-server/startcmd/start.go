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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	ariesmysqlstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mysql"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	acrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
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
	vctclient "github.com/trustbloc/vct/pkg/client/vct"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
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
	"github.com/trustbloc/orb/pkg/anchor/policy"
	policyhandler "github.com/trustbloc/orb/pkg/anchor/policy/resthandler"
	"github.com/trustbloc/orb/pkg/anchor/writer"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	ipfscas "github.com/trustbloc/orb/pkg/cas/ipfs"
	"github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/config"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/orb/pkg/context/opqueue"
	orbpc "github.com/trustbloc/orb/pkg/context/protocol/client"
	orbpcp "github.com/trustbloc/orb/pkg/context/protocol/provider"
	localdiscovery "github.com/trustbloc/orb/pkg/discovery/did/local"
	discoveryclient "github.com/trustbloc/orb/pkg/discovery/endpoint/client"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/document/resolvehandler"
	"github.com/trustbloc/orb/pkg/document/updatehandler"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/ldcontextrest"
	"github.com/trustbloc/orb/pkg/metrics"
	"github.com/trustbloc/orb/pkg/nodeinfo"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/protocolversion/factoryregistry"
	"github.com/trustbloc/orb/pkg/pubsub/amqp"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/resolver/resource"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry/didanchorinfo"
	casstore "github.com/trustbloc/orb/pkg/store/cas"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	"github.com/trustbloc/orb/pkg/store/operation"
	"github.com/trustbloc/orb/pkg/store/vcstatus"
	vcstore "github.com/trustbloc/orb/pkg/store/verifiable"
	proofstore "github.com/trustbloc/orb/pkg/store/witness"
	"github.com/trustbloc/orb/pkg/store/wrapper"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/webcas"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	masterKeyURI = "local-lock://custom/master/key/"

	defaultMaxWitnessDelay                   = 600 * time.Second // 10 minutes
	defaultSyncTimeout                       = 1
	defaulthttpSignaturesEnabled             = true
	defaultDidDiscoveryEnabled               = false
	defaultAllowedOriginsOptimizationEnabled = false
	defaultCreateDocumentStoreEnabled        = false
	defaultLocalCASReplicateInIPFSEnabled    = false
	defaultDevModeEnabled                    = false
	defaultPolicyCacheExpiry                 = 30 * time.Second
	defaultCasCacheSize                      = 1000

	unpublishedDIDLabel = "uAAA"
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/v1"

	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"

	activityPubServicesPath = "/services/orb"

	casPath = "/cas"

	kmsKeyType             = kms.ED25519Type
	verificationMethodType = "Ed25519VerificationKey2018"

	webKeyStoreKey = "web-key-store"
	kidKey         = "kid"
)

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

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
		}, parameters.syncTimeout)
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
	}, parameters.syncTimeout)
}

func importPrivateKey(km kms.KeyManager, parameters *orbParameters, cfg storage.Store) error {
	return getOrInit(cfg, kidKey, &parameters.keyID, func() (interface{}, error) {
		keyBytes, err := base64.RawStdEncoding.DecodeString(parameters.privateKeyBase64)
		if err != nil {
			return nil, err
		}

		keyID, _, err := km.ImportPrivateKey(ed25519.PrivateKey(keyBytes), kms.ED25519, kms.WithKeyID(parameters.keyID))
		if err == nil && strings.TrimSpace(keyID) == "" {
			return nil, errors.New("import private key: keyID is empty")
		}

		return keyID, err
	}, parameters.syncTimeout)
}

// nolint: gocyclo,funlen,gocognit
func startOrbServices(parameters *orbParameters) error {
	if parameters.logLevel != "" {
		setLogLevels(logger, parameters.logLevel)
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

	casIRI := mustParseURL(parameters.externalEndpoint, casPath)

	var coreCASClient extendedcasclient.Client

	switch {
	case strings.EqualFold(parameters.casType, "ipfs"):
		logger.Infof("Initializing Orb CAS with IPFS.")
		coreCASClient = ipfscas.New(parameters.ipfsURL, parameters.ipfsTimeout, defaultCasCacheSize, metrics.Get(),
			extendedcasclient.WithCIDVersion(parameters.cidVersion))
	case strings.EqualFold(parameters.casType, "local"):
		logger.Infof("Initializing Orb CAS with local storage provider.")

		var err error

		if parameters.localCASReplicateInIPFSEnabled {
			logger.Infof("Local CAS writes will be replicated in IPFS.")

			coreCASClient, err = casstore.New(storeProviders.provider, casIRI.String(),
				ipfscas.New(parameters.ipfsURL, parameters.ipfsTimeout, defaultCasCacheSize, metrics.Get(),
					extendedcasclient.WithCIDVersion(parameters.cidVersion)),
				metrics.Get(), defaultCasCacheSize, extendedcasclient.WithCIDVersion(parameters.cidVersion))
			if err != nil {
				return err
			}
		} else {
			coreCASClient, err = casstore.New(storeProviders.provider, casIRI.String(), nil,
				metrics.Get(), defaultCasCacheSize, extendedcasclient.WithCIDVersion(parameters.cidVersion))
			if err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("%s is not a valid CAS type. It must be either local or ipfs", parameters.casType)
	}

	didAnchors, err := didanchorstore.New(storeProviders.provider)
	if err != nil {
		return err
	}

	opStore, err := operation.New(storeProviders.provider)
	if err != nil {
		return err
	}

	defaultContexts := ldcontext.MustGetAll()

	jldStorageProvider := cachedstore.NewProvider(storeProviders.provider, ariesmemstorage.NewProvider())

	contextStore, err := ldstore.NewContextStore(jldStorageProvider)
	if err != nil {
		return fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(jldStorageProvider)
	if err != nil {
		return fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	orbDocumentLoader, err := ld.NewDocumentLoader(ldStore, ld.WithExtraContexts(defaultContexts...))
	if err != nil {
		return fmt.Errorf("failed to load Orb contexts: %s", err.Error())
	}

	useHTTPOpt := false
	webFingerURIScheme := "https"

	if parameters.enableDevMode {
		useHTTPOpt = true
		webFingerURIScheme = "http"
	}

	vdr := vdr.New(
		vdr.WithVDR(&webVDR{http: httpClient, VDR: vdrweb.New(), useHTTPOpt: useHTTPOpt}),
	)

	if parameters.keyID == "" {
		if err = createKID(km, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	if parameters.keyID != "" && parameters.privateKeyBase64 != "" {
		if err = importPrivateKey(km, parameters, configStore); err != nil {
			return fmt.Errorf("import kid: %w", err)
		}
	}

	apServicePublicKeyIRI := mustParseURL(parameters.externalEndpoint,
		fmt.Sprintf("%s/keys/%s", activityPubServicesPath, aphandler.MainKeyID))

	apGetSigner, apPostSigner := getActivityPubSigners(parameters, km, cr)

	t := transport.New(httpClient, apServicePublicKeyIRI, apGetSigner, apPostSigner)

	wfClient := wfclient.New(wfclient.WithHTTPClient(httpClient))

	webCASResolver := resolver.NewWebCASResolver(t, wfClient, webFingerURIScheme)

	var ipfsReader *ipfscas.Client
	var casResolver *resolver.Resolver
	if parameters.ipfsURL != "" {
		ipfsReader = ipfscas.New(parameters.ipfsURL, parameters.ipfsTimeout, defaultCasCacheSize, metrics.Get(),
			extendedcasclient.WithCIDVersion(parameters.cidVersion))
		casResolver = resolver.New(coreCASClient, ipfsReader, webCASResolver, metrics.Get())
	} else {
		casResolver = resolver.New(coreCASClient, nil, webCASResolver, metrics.Get())
	}

	graphProviders := &graph.Providers{
		CasResolver: casResolver,
		CasWriter:   coreCASClient,
		Pkf:         verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher(),
		DocLoader:   orbDocumentLoader,
	}

	anchorGraph := graph.New(graphProviders)

	// get protocol client provider
	pcp, err := getProtocolClientProvider(parameters, coreCASClient, casResolver, opStore, anchorGraph)
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
		Metrics:    metrics.Get(),
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

	didAnchoringInfoProvider := didanchorinfo.New(parameters.didNamespace, didAnchors, opProcessor)

	// add any additional supported namespaces to resource registry (for now we have just one)
	resourceRegistry := registry.New(registry.WithResourceInfoProvider(didAnchoringInfoProvider))
	logger.Debugf("started resource registry: %+v", resourceRegistry)

	apServiceIRI := mustParseURL(parameters.externalEndpoint, activityPubServicesPath)

	var pubSub pubSub

	if parameters.mqURL != "" {
		pubSub = amqp.New(amqp.Config{
			URI:                        parameters.mqURL,
			MaxConnectionSubscriptions: parameters.mqMaxConnectionSubscriptions,
		})
	} else {
		pubSub = mempubsub.New(mempubsub.DefaultConfig())
	}

	apConfig := &apservice.Config{
		ServiceEndpoint:        activityPubServicesPath,
		ServiceIRI:             apServiceIRI,
		MaxWitnessDelay:        parameters.maxWitnessDelay,
		VerifyActorInSignature: parameters.httpSignaturesEnabled,
	}

	apStore, err := createActivityPubStore(parameters, apConfig.ServiceEndpoint)
	if err != nil {
		return err
	}

	pubKey, err := km.ExportPubKeyBytes(parameters.keyID)
	if err != nil {
		return fmt.Errorf("failed to export pub key: %w", err)
	}

	publicKey, err := getActivityPubPublicKey(pubKey, apServiceIRI, apServicePublicKeyIRI)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	// TODO: Pass config from startup params
	apClient := client.New(client.Config{}, t)

	apSigVerifier := getActivityPubVerifier(parameters, km, cr, apClient)

	monitoringSvc, err := monitoring.New(storeProviders.provider, orbDocumentLoader, wfClient, monitoring.WithHTTPClient(httpClient))
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
			Metrics:       metrics.Get(),
		},
		pubSub)

	witness := vct.New(parameters.vctURL, vcSigner, metrics.Get(),
		vct.WithHTTPClient(httpClient),
		vct.WithDocumentLoader(orbDocumentLoader),
	)

	if parameters.vctURL != "" {
		err = vctclient.New(parameters.vctURL, vctclient.WithHTTPClient(httpClient)).
			AddJSONLDContexts(context.Background(), defaultContexts...)
		if err != nil {
			return fmt.Errorf("failed to add contexts: %w", err)
		}
	}

	var activityPubService *apservice.Service

	// create new observer and start it
	providers := &observer.Providers{
		ProtocolClientProvider: pcp,
		AnchorGraph:            anchorGraph,
		DidAnchors:             didAnchors,
		PubSub:                 pubSub,
		Metrics:                metrics.Get(),
		Outbox:                 func() observer.Outbox { return activityPubService.Outbox() },
	}

	o, err := observer.New(providers, observer.WithDiscoveryDomain(parameters.discoveryDomain))
	if err != nil {
		return fmt.Errorf("failed to create observer: %s", err.Error())
	}

	resourceResolver := resource.New(httpClient, ipfsReader)

	activityPubService, err = apservice.New(apConfig,
		apStore, t, apSigVerifier, pubSub, apClient, resourceResolver, metrics.Get(),
		apspi.WithProofHandler(proofHandler),
		apspi.WithWitness(witness),
		apspi.WithAnchorCredentialHandler(credential.New(
			o.Publisher(), casResolver, orbDocumentLoader, monitoringSvc, parameters.maxWitnessDelay,
		)),
		// TODO: Define the following ActivityPub handlers.
		// apspi.WithWitnessInvitationAuth(inviteWitnessAuth),
		// apspi.WithFollowerAuth(followerAuth),
		// apspi.WithUndeliverableHandler(undeliverableHandler),
		// apspi.WithAnchorEventNotificationHandler(anchorEventHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	o.Start()

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
		WFClient:      wfClient,
	}

	anchorWriter, err := writer.New(parameters.didNamespace,
		apServiceIRI, casIRI,
		anchorWriterProviders,
		o.Publisher(), pubSub,
		parameters.maxWitnessDelay,
		parameters.signWithLocalWitness,
		orbDocumentLoader, resourceResolver,
		metrics.Get())
	if err != nil {
		return fmt.Errorf("failed to create writer: %s", err.Error())
	}

	opQueue, err := opqueue.New(opqueue.Config{PoolSize: parameters.opQueuePoolSize}, pubSub, metrics.Get())
	if err != nil {
		return fmt.Errorf("failed to create operation queue: %s", err.Error())
	}

	// create new batch writer
	batchWriter, err := batch.New(parameters.didNamespace,
		sidetreecontext.New(pc, anchorWriter, opQueue),
		batch.WithBatchTimeout(parameters.batchWriterTimeout))
	if err != nil {
		return fmt.Errorf("failed to create batch writer: %s", err.Error())
	}

	// start routine for creating batches
	batchWriter.Start()
	logger.Infof("started batch writer")

	logger.Infof("started observer")

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		opProcessor,
		dochandler.WithDomain("https:"+u.Host),
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
		PageSize:               parameters.activityPubPageSize,
	}

	var resolveHandlerOpts []resolvehandler.Option
	resolveHandlerOpts = append(resolveHandlerOpts, resolvehandler.WithUnpublishedDIDLabel(unpublishedDIDLabel))
	resolveHandlerOpts = append(resolveHandlerOpts, resolvehandler.WithEnableDIDDiscovery(parameters.didDiscoveryEnabled))

	var updateHandlerOpts []updatehandler.Option

	if parameters.createDocumentStoreEnabled {
		store, openErr := storeProviders.provider.OpenStore("create-document")
		if openErr != nil {
			return fmt.Errorf("failed to open 'create-document' store: %w", openErr)
		}

		resolveHandlerOpts = append(resolveHandlerOpts, resolvehandler.WithCreateDocumentStore(store))
		updateHandlerOpts = append(updateHandlerOpts, updatehandler.WithCreateDocumentStore(store))
	}

	discoveryClient, err := discoveryclient.New(orbDocumentLoader,
		&discoveryCAS{resolver: casResolver},
		discoveryclient.WithNamespace(parameters.didNamespace),
		discoveryclient.WithHTTPClient(httpClient),
	)

	didDiscovery := localdiscovery.New(parameters.didNamespace, o.Publisher(), discoveryClient)

	orbDocResolveHandler := resolvehandler.NewResolveHandler(
		parameters.didNamespace,
		didDocHandler,
		didDiscovery,
		anchorGraph,
		metrics.Get(),
		resolveHandlerOpts...,
	)

	orbDocUpdateHandler := updatehandler.New(didDocHandler, metrics.Get(), updateHandlerOpts...)

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
		ResourceRegistry:          resourceRegistry,
	})
	if err != nil {
		return fmt.Errorf("discovery rest: %w", err)
	}

	ctxRest, err := ldcontextrest.New(jldStorageProvider)
	if err != nil {
		return fmt.Errorf("ldcontext rest: %w", err)
	}

	nodeInfoService := nodeinfo.NewService(apStore, apServiceIRI, parameters.nodeInfoRefreshInterval)

	handlers := make([]restcommon.HTTPHandler, 0)

	handlers = append(handlers,
		auth.NewHandlerWrapper(authCfg, diddochandler.NewUpdateHandler(baseUpdatePath, orbDocUpdateHandler, pc)),
		auth.NewHandlerWrapper(authCfg, diddochandler.NewResolveHandler(baseResolvePath, orbDocResolveHandler)),
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
		aphandler.NewLikes(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewShares(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewPostOutbox(apEndpointCfg, activityPubService.Outbox(), apStore, apSigVerifier),
		aphandler.NewActivity(apEndpointCfg, apStore, apSigVerifier),
		webcas.New(apEndpointCfg, apStore, apSigVerifier, coreCASClient),
		auth.NewHandlerWrapper(authCfg, policyhandler.New(configStore)),
		ctxRest,
		auth.NewHandlerWrapper(authCfg, nodeinfo.NewHandler(nodeinfo.V2_0, nodeInfoService)),
		auth.NewHandlerWrapper(authCfg, nodeinfo.NewHandler(nodeinfo.V2_1, nodeInfoService)),
	)

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		handlers...,
	)

	metricsHttpServer := httpserver.New(
		parameters.hostMetricsURL, "", "",
		metrics.NewHandler(),
	)

	activityPubService.Start()

	nodeInfoService.Start()

	err = metricsHttpServer.Start()
	if err != nil {
		return fmt.Errorf("start metrics HTTP server at %s: %w", parameters.hostMetricsURL, err)
	}

	srv := &HTTPServer{}

	err = srv.Start(httpServer)
	if err != nil {
		return err
	}

	logger.Infof("Stopping Orb services ...")

	nodeInfoService.Stop()

	batchWriter.Stop()

	o.Stop()

	activityPubService.Stop()

	if err := pubSub.Close(); err != nil {
		logger.Warnf("Error closing publisher/subscriber: %s", err)
	}

	logger.Infof("Stopped Orb services.")

	return nil
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

func createActivityPubStore(parameters *orbParameters, serviceEndpoint string) (activitypubspi.Store, error) {
	var apStore activitypubspi.Store

	if strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption) {
		couchDBProvider, err := ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix+"_"+serviceEndpoint),
			ariescouchdbstorage.WithLogger(logger))
		if err != nil {
			return nil, fmt.Errorf("failed to create CouchDB storage provider for ActivityPub: %w", err)
		}

		couchDBProviderWrapper := wrapper.NewProvider(couchDBProvider, "CouchDB")

		apStore, err = apariesstore.New(couchDBProviderWrapper, serviceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aries storage provider for ActivityPub: %w", err)
		}
	} else if strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption) {
		// The "/" characters below are replaced with "-" since MongoDB database names can't contain those characters.
		databasePrefix := fmt.Sprintf("%s%s_", parameters.dbParameters.databasePrefix,
			strings.ReplaceAll(serviceEndpoint, "/", "-"))

		mongoDBProvider := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(databasePrefix),
			ariesmongodbstorage.WithLogger(logger))

		mongoDBProviderWrapper := wrapper.NewProvider(mongoDBProvider, "MongoDB")

		var err error

		apStore, err = apariesstore.New(mongoDBProviderWrapper, serviceEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aries storage provider for ActivityPub: %w", err)
		}
	} else {
		apStore = apmemstore.New(serviceEndpoint)
	}

	return apStore, nil
}

type discoveryCAS struct {
	resolver common.CASResolver
}

func (dc *discoveryCAS) Read(key string) ([]byte, error) {
	return dc.resolver.Resolve(nil, key, nil)
}

type webVDR struct {
	http *http.Client
	*vdrweb.VDR
	useHTTPOpt bool
}

func (w *webVDR) Read(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	if w.useHTTPOpt {
		opts = append(opts, vdrapi.WithOption(vdrweb.UseHTTPOpt, true))
	}

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
		couchDBProvider, err :=
			ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
				ariescouchdbstorage.WithLogger(logger))
		if err != nil {
			return &storageProviders{}, err
		}

		edgeServiceProvs.provider = wrapper.NewProvider(couchDBProvider, "CouchDB")
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		mongoDBProvider := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger))

		edgeServiceProvs.provider = wrapper.NewProvider(mongoDBProvider, "MongoDB")

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
		couchDBProvider, err :=
			ariescouchdbstorage.NewProvider(parameters.dbParameters.kmsSecretsDatabaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.kmsSecretsDatabasePrefix))

		edgeServiceProvs.kmsSecretsProvider = wrapper.NewProvider(couchDBProvider, "CouchDB")
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
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMongoDBOption):
		mongoDBProvider := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger))

		edgeServiceProvs.kmsSecretsProvider = wrapper.NewProvider(mongoDBProvider, "MongoDB")
	default:
		return &storageProviders{}, fmt.Errorf("key database type not set to a valid type." +
			" run start --help to see the available options")
	}

	return &edgeServiceProvs, nil
}

func getOrInit(cfg storage.Store, keyID string, v interface{}, initFn func() (interface{}, error),
	timeout uint64) error {
	src, err := cfg.Get(keyID)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get config value for %q: %w", keyID, err)
	}

	if err == nil {
		time.Sleep(time.Second * time.Duration(timeout))

		var src2 []byte

		src2, err = cfg.Get(keyID)
		if err != nil && errors.Is(err, storage.ErrDataNotFound) {
			return getOrInit(cfg, keyID, v, initFn, timeout)
		}

		if err != nil {
			return fmt.Errorf("get config value for %q: %w", keyID, err)
		}

		if reflect.DeepEqual(src, src2) {
			return json.Unmarshal(src, v) // nolint: wrapcheck
		}

		return getOrInit(cfg, keyID, v, initFn, timeout)
	}

	val, err := initFn()
	if err != nil {
		return fmt.Errorf("init config value for %q: %w", keyID, err)
	}

	src, err = json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal config value for %q: %w", keyID, err)
	}

	if err = cfg.Put(keyID, src); err != nil {
		return fmt.Errorf("marshal config value for %q: %w", keyID, err)
	}

	logger.Debugf("Stored KMS key [%s] with %s", keyID, src)

	return getOrInit(cfg, keyID, v, initFn, timeout)
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
	cr acrypto.Crypto, apClient *client.Client) signatureVerifier {
	if parameters.httpSignaturesEnabled {
		return httpsig.NewVerifier(apClient, cr, km)
	}

	logger.Warnf("HTTP signature verification for ActivityPub is disabled.")

	return &noOpVerifier{}
}

type noOpVerifier struct{}

func (v *noOpVerifier) VerifyRequest(req *http.Request) (bool, *url.URL, error) {
	return true, nil, nil
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}
