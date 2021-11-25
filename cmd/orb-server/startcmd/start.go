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
	"net"
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
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	acrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrweb "github.com/hyperledger/aries-framework-go/pkg/vdr/web"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/httpsig"
	aphandler "github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apservice "github.com/trustbloc/orb/pkg/activitypub/service"
	"github.com/trustbloc/orb/pkg/activitypub/service/acceptlist"
	"github.com/trustbloc/orb/pkg/activitypub/service/activityhandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/monitoring"
	apspi "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	"github.com/trustbloc/orb/pkg/activitypub/service/vct"
	apariesstore "github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	apmemstore "github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	activitypubspi "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorevent/vcresthandler"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/handler/acknowlegement"
	"github.com/trustbloc/orb/pkg/anchor/handler/credential"
	"github.com/trustbloc/orb/pkg/anchor/handler/proof"
	"github.com/trustbloc/orb/pkg/anchor/linkstore"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
	policyhandler "github.com/trustbloc/orb/pkg/anchor/witness/policy/resthandler"
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
	"github.com/trustbloc/orb/pkg/document/remoteresolver"
	"github.com/trustbloc/orb/pkg/document/resolvehandler"
	"github.com/trustbloc/orb/pkg/document/updatehandler"
	"github.com/trustbloc/orb/pkg/document/updatehandler/decorator"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/httpserver/auth/signature"
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
	anchoreventstore "github.com/trustbloc/orb/pkg/store/anchorevent"
	casstore "github.com/trustbloc/orb/pkg/store/cas"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	"github.com/trustbloc/orb/pkg/store/expiry"
	opstore "github.com/trustbloc/orb/pkg/store/operation"
	unpublishedopstore "github.com/trustbloc/orb/pkg/store/operation/unpublished"
	"github.com/trustbloc/orb/pkg/store/vcstatus"
	proofstore "github.com/trustbloc/orb/pkg/store/witness"
	"github.com/trustbloc/orb/pkg/store/wrapper"
	"github.com/trustbloc/orb/pkg/taskmgr"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/webcas"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	masterKeyURI = "local-lock://custom/master/key/"

	defaultMaxWitnessDelay                = 600 * time.Second // 10 minutes
	defaultSyncTimeout                    = 1
	defaulthttpSignaturesEnabled          = true
	defaultDidDiscoveryEnabled            = false
	defaultCreateDocumentStoreEnabled     = false
	defaultUpdateDocumentStoreEnabled     = false
	defaultIncludeUnpublishedOperations   = false
	defaultIncludePublishedOperations     = false
	defaultResolveFromAnchorOrigin        = false
	defaultVerifyLatestFromAnchorOrigin   = false
	defaultLocalCASReplicateInIPFSEnabled = false
	defaultDevModeEnabled                 = false
	defaultPolicyCacheExpiry              = 30 * time.Second
	defaultCasCacheSize                   = 1000

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

	rootCAs, err := tlsutils.GetCertPool(parameters.tlsParams.systemCertPool, parameters.tlsParams.caCerts)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	if parameters.enableDevMode {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint: gosec
		}
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   parameters.httpDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient := &http.Client{
		Timeout:   parameters.httpTimeout,
		Transport: httpTransport,
	}

	km, cr, err := createKMSAndCrypto(parameters, httpClient, storeProviders.kmsSecretsProvider, configStore)
	if err != nil {
		return err
	}

	// TODO: If we decide to offer deactivate and recover we should configure this
	parameters.updateDocumentStoreTypes = []operation.Type{operation.TypeUpdate}

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

	opStore, err := opstore.New(storeProviders.provider)
	if err != nil {
		return err
	}

	ldStorageProvider := cachedstore.NewProvider(storeProviders.provider, ariesmemstorage.NewProvider())

	contextStore, err := ldstore.NewContextStore(ldStorageProvider)
	if err != nil {
		return fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(ldStorageProvider)
	if err != nil {
		return fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	orbDocumentLoader, err := createJSONLDDocumentLoader(ldStore, httpClient, parameters.contextProviderURLs)
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
		DocLoader:   orbDocumentLoader,
	}

	anchorGraph := graph.New(graphProviders)

	taskMgr := taskmgr.New(configStore, parameters.taskMgrCheckInterval)

	expiryService := expiry.NewService(taskMgr, parameters.dataExpiryCheckInterval)

	var updateDocumentStore *unpublishedopstore.Store
	if parameters.updateDocumentStoreEnabled {
		updateDocumentStore, err = unpublishedopstore.New(storeProviders.provider,
			parameters.unpublishedOperationLifespan, expiryService)
		if err != nil {
			return fmt.Errorf("failed to create unpublished document store: %w", err)
		}
	}

	// get protocol client provider
	pcp, err := getProtocolClientProvider(parameters, coreCASClient, casResolver, opStore, storeProviders.provider, updateDocumentStore)
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

	anchorEventStore, err := anchoreventstore.New(storeProviders.provider, orbDocumentLoader)
	if err != nil {
		return fmt.Errorf("failed to create anchor event store: %s", err.Error())
	}

	witnessProofStore, err := proofstore.New(storeProviders.provider, expiryService, parameters.maxWitnessDelay)
	if err != nil {
		return fmt.Errorf("failed to create proof store: %s", err.Error())
	}

	vcStatusStore, err := vcstatus.New(storeProviders.provider, expiryService, parameters.maxWitnessDelay)
	if err != nil {
		return fmt.Errorf("failed to create vc status store: %s", err.Error())
	}

	var processorOpts []processor.Option
	if parameters.updateDocumentStoreEnabled {
		processorOpts = append(processorOpts, processor.WithUnpublishedOperationStore(updateDocumentStore))
	}

	opProcessor := processor.New(parameters.didNamespace, opStore, pc, processorOpts...)

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
			AnchorEventStore: anchorEventStore,
			StatusStore:      vcStatusStore,
			MonitoringSvc:    monitoringSvc,
			DocLoader:        orbDocumentLoader,
			WitnessStore:     witnessProofStore,
			WitnessPolicy:    witnessPolicy,
			Metrics:          metrics.Get(),
		},
		pubSub)

	witness := vct.New(parameters.vctURL, vcSigner, metrics.Get(),
		vct.WithHTTPClient(httpClient),
		vct.WithDocumentLoader(orbDocumentLoader),
	)

	var activityPubService *apservice.Service

	resourceResolver := resource.New(httpClient, ipfsReader)

	anchorLinkStore, err := linkstore.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	// create new observer and start it
	providers := &observer.Providers{
		ProtocolClientProvider: pcp,
		AnchorGraph:            anchorGraph,
		DidAnchors:             didAnchors,
		PubSub:                 pubSub,
		Metrics:                metrics.Get(),
		Outbox:                 func() observer.Outbox { return activityPubService.Outbox() },
		WebFingerResolver:      resourceResolver,
		CASResolver:            casResolver,
		DocLoader:              orbDocumentLoader,
		Pkf:                    verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher(),
		AnchorLinkStore:        anchorLinkStore,
	}

	o, err := observer.New(apConfig.ServiceIRI, providers,
		observer.WithDiscoveryDomain(parameters.discoveryDomain),
		observer.WithSubscriberPoolSize(parameters.observerQueuePoolSize),
	)
	if err != nil {
		return fmt.Errorf("failed to create observer: %s", err.Error())
	}

	anchorEventHandler := acknowlegement.New(anchorLinkStore)

	activityPubService, err = apservice.New(apConfig,
		apStore, t, apSigVerifier, pubSub, apClient, resourceResolver, metrics.Get(),
		apspi.WithProofHandler(proofHandler),
		apspi.WithWitness(witness),
		apspi.WithAnchorEventHandler(credential.New(
			o.Publisher(), casResolver, orbDocumentLoader, monitoringSvc, parameters.maxWitnessDelay,
		)),
		apspi.WithInviteWitnessAuth(NewAcceptRejectHandler(activityhandler.InviteWitnessType, parameters.inviteWitnessAuthPolicy, configStore)),
		apspi.WithFollowAuth(NewAcceptRejectHandler(activityhandler.FollowType, parameters.followAuthPolicy, configStore)),
		apspi.WithAnchorEventAcknowledgementHandler(anchorEventHandler),
		// TODO: Define the following ActivityPub handlers.
		// apspi.WithUndeliverableHandler(undeliverableHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	o.Start()

	vcStore, err := storeProviders.provider.OpenStore("verifiable")
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	anchorWriterProviders := &writer.Providers{
		AnchorGraph:      anchorGraph,
		DidAnchors:       didAnchors,
		AnchorBuilder:    vcBuilder,
		AnchorEventStore: anchorEventStore,
		VCStatusStore:    vcStatusStore,
		OpProcessor:      opProcessor,
		Outbox:           activityPubService.Outbox(),
		Witness:          witness,
		Signer:           vcSigner,
		MonitoringSvc:    monitoringSvc,
		ActivityStore:    apStore,
		WitnessStore:     witnessProofStore,
		WitnessPolicy:    witnessPolicy,
		WFClient:         wfClient,
		DocumentLoader:   orbDocumentLoader,
		VCStore:          vcStore,
	}

	anchorWriter, err := writer.New(parameters.didNamespace,
		apServiceIRI, casIRI,
		anchorWriterProviders,
		o.Publisher(), pubSub,
		parameters.maxWitnessDelay,
		parameters.signWithLocalWitness,
		resourceResolver,
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

	// start the task manager
	taskMgr.Start()

	var didDocHandlerOpts []dochandler.Option
	didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithDomain("https:"+u.Host))
	didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithLabel(unpublishedDIDLabel))

	if parameters.updateDocumentStoreEnabled {
		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithUnpublishedOperationStore(updateDocumentStore, parameters.updateDocumentStoreTypes))
	}

	endpointClient, err := discoveryclient.New(orbDocumentLoader,
		&discoveryCAS{resolver: casResolver},
		discoveryclient.WithNamespace(parameters.didNamespace),
		discoveryclient.WithHTTPClient(httpClient),
	)

	if parameters.verifyLatestFromAnchorOrigin {

		operationDecorator := decorator.New(parameters.didNamespace,
			parameters.externalEndpoint,
			opProcessor,
			endpointClient,
			remoteresolver.New(t),
		)

		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithOperationDecorator(operationDecorator))
	}

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		opProcessor,
		didDocHandlerOpts...,
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
	resolveHandlerOpts = append(resolveHandlerOpts, resolvehandler.WithEnableResolutionFromAnchorOrigin(parameters.resolveFromAnchorOrigin))

	var updateHandlerOpts []updatehandler.Option

	if parameters.createDocumentStoreEnabled {
		store, openErr := storeProviders.provider.OpenStore("create-document")
		if openErr != nil {
			return fmt.Errorf("failed to open 'create-document' store: %w", openErr)
		}

		resolveHandlerOpts = append(resolveHandlerOpts, resolvehandler.WithCreateDocumentStore(store))
		updateHandlerOpts = append(updateHandlerOpts, updatehandler.WithCreateDocumentStore(store))
	}

	didDiscovery := localdiscovery.New(parameters.didNamespace, o.Publisher(), endpointClient)

	orbDocResolveHandler := resolvehandler.NewResolveHandler(
		parameters.didNamespace,
		didDocHandler,
		didDiscovery,
		parameters.externalEndpoint,
		endpointClient,
		remoteresolver.New(t),
		anchorGraph,
		metrics.Get(),
		resolveHandlerOpts...,
	)

	orbDocUpdateHandler := updatehandler.New(didDocHandler, metrics.Get(), updateHandlerOpts...)

	// create discovery rest api
	endpointDiscoveryOp, err := discoveryrest.New(
		&discoveryrest.Config{
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
		},
		&discoveryrest.Providers{
			ResourceRegistry: resourceRegistry,
			CAS:              coreCASClient,
			AnchorLinkStore:  anchorLinkStore,
		})
	if err != nil {
		return fmt.Errorf("discovery rest: %w", err)
	}

	var usingMongoDB bool

	if parameters.dbParameters.databaseType == databaseTypeMongoDBOption {
		usingMongoDB = true
	}

	if !usingMongoDB {
		logger.Warnf("The NodeInfo service is not optimized for storage providers other than MongoDB. " +
			"With a large database, it may consume lots of memory. " +
			"See https://github.com/trustbloc/orb/issues/797 for more information.")
	}

	nodeInfoLogger := log.New("nodeinfo")

	nodeInfoService := nodeinfo.NewService(apServiceIRI, parameters.nodeInfoRefreshInterval, apStore, usingMongoDB,
		nodeInfoLogger)

	handlers := make([]restcommon.HTTPHandler, 0)

	handlers = append(handlers,
		auth.NewHandlerWrapper(authCfg, diddochandler.NewUpdateHandler(baseUpdatePath, orbDocUpdateHandler, pc)),
		signature.NewHandlerWrapper(diddochandler.NewResolveHandler(baseResolvePath, orbDocResolveHandler), apEndpointCfg, apStore, apSigVerifier),
		activityPubService.InboxHTTPHandler(),
		aphandler.NewServices(apEndpointCfg, apStore, publicKey),
		aphandler.NewPublicKeys(apEndpointCfg, apStore, publicKey),
		aphandler.NewFollowers(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewFollowing(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewOutbox(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		aphandler.NewInbox(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		aphandler.NewWitnesses(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewWitnessing(apEndpointCfg, apStore, apSigVerifier),
		aphandler.NewLiked(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		aphandler.NewLikes(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		aphandler.NewShares(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		aphandler.NewPostOutbox(apEndpointCfg, activityPubService.Outbox(), apStore, apSigVerifier),
		aphandler.NewActivity(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending),
		webcas.New(apEndpointCfg, apStore, apSigVerifier, coreCASClient),
		auth.NewHandlerWrapper(authCfg, policyhandler.New(configStore)),
		auth.NewHandlerWrapper(authCfg, nodeinfo.NewHandler(nodeinfo.V2_0, nodeInfoService, nodeInfoLogger)),
		auth.NewHandlerWrapper(authCfg, nodeinfo.NewHandler(nodeinfo.V2_1, nodeInfoService, nodeInfoLogger)),
		auth.NewHandlerWrapper(authCfg, vcresthandler.New(vcStore)),
	)

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	for _, handler := range ldrest.New(ldsvc.New(ldStore)).GetRESTHandlers() {
		handlers = append(handlers, auth.NewHandlerWrapper(authCfg, &httpHandler{handler}))
	}

	if parameters.followAuthPolicy == acceptListPolicy || parameters.inviteWitnessAuthPolicy == acceptListPolicy {
		// Register endpoints to manage the 'accept list'.
		handlers = append(handlers, auth.NewHandlerWrapper(
			authCfg,
			aphandler.NewAcceptListWriter(apEndpointCfg, acceptlist.NewManager(configStore)),
		))
		handlers = append(handlers, auth.NewHandlerWrapper(
			authCfg,
			aphandler.NewAcceptListReader(apEndpointCfg, acceptlist.NewManager(configStore))),
		)
	}

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
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

	taskMgr.Stop()

	if err := pubSub.Close(); err != nil {
		logger.Warnf("Error closing publisher/subscriber: %s", err)
	}

	logger.Infof("Stopped Orb services.")

	return nil
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, casResolver common.CASResolver,
	opStore common.OperationStore, provider storage.Provider,
	unpublishedOpStore *unpublishedopstore.Store) (*orbpcp.ClientProvider, error) {
	versions := []string{"1.0"}

	sidetreeCfg := config.Sidetree{
		MethodContext:                parameters.methodContext,
		EnableBase:                   parameters.baseEnabled,
		AnchorOrigins:                parameters.allowedOrigins,
		UnpublishedOpStore:           unpublishedOpStore,
		UpdateDocumentStoreTypes:     parameters.updateDocumentStoreTypes,
		IncludeUnpublishedOperations: parameters.includeUnpublishedOperations,
		IncludePublishedOperations:   parameters.includePublishedOperations,
	}

	registry := factoryregistry.New()

	var protocolVersions []protocol.Version
	for _, version := range versions {
		pv, err := registry.CreateProtocolVersion(version, casClient, casResolver, opStore, provider, &sidetreeCfg)
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

		apStore, err = apariesstore.New(serviceEndpoint, couchDBProviderWrapper, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aries storage provider for ActivityPub: %w", err)
		}
	} else if strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption) {
		// The "/" characters below are replaced with "-" since MongoDB database names can't contain those characters.
		databasePrefix := fmt.Sprintf("%s%s_", parameters.dbParameters.databasePrefix,
			strings.ReplaceAll(serviceEndpoint, "/", "-"))

		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(databasePrefix),
			ariesmongodbstorage.WithLogger(logger),
			ariesmongodbstorage.WithTimeout(parameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider for ActivityPub: %w", err)
		}

		mongoDBProviderWrapper := wrapper.NewProvider(mongoDBProvider, "MongoDB")

		apStore, err = apariesstore.New(serviceEndpoint, mongoDBProviderWrapper, true)
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
	data, _, err := dc.resolver.Resolve(nil, key, nil)

	return data, err
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
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger),
			ariesmongodbstorage.WithTimeout(parameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider: %w", err)
		}

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
	case strings.EqualFold(parameters.dbParameters.kmsSecretsDatabaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger),
			ariesmongodbstorage.WithTimeout(parameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider: %w", err)
		}

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

type httpHandler struct {
	a ariesrest.Handler
}

func (h *httpHandler) Path() string {
	return h.a.Path()
}

func (h *httpHandler) Method() string {
	return h.a.Method()
}

func (h *httpHandler) Handler() restcommon.HTTPRequestHandler {
	return restcommon.HTTPRequestHandler(h.a.Handle())
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

func createJSONLDDocumentLoader(ldStore *ldStoreProvider, httpClient *http.Client,
	providerURLs []string) (jsonld.DocumentLoader, error) {
	loaderOpts := []ld.DocumentLoaderOpts{ld.WithExtraContexts(ldcontext.MustGetAll()...)}

	for _, u := range providerURLs {
		loaderOpts = append(loaderOpts,
			ld.WithRemoteProvider(
				remote.NewProvider(u, remote.WithHTTPClient(httpClient)),
			),
		)
	}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}

func NewAcceptRejectHandler(targetType string, policy acceptRejectPolicy, configStore storage.Store) apspi.ActorAuth {
	switch policy {
	case acceptListPolicy:
		return activityhandler.NewAcceptListAuthHandler(targetType, acceptlist.NewManager(configStore))
	default:
		return &activityhandler.AcceptAllActorsAuth{}
	}
}
