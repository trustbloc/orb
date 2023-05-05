/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
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
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	awssvc "github.com/trustbloc/kms/pkg/aws"
	"github.com/trustbloc/logutil-go/pkg/log"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/internal/pkg/tlsutil"
	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/httpsig"
	aphandler "github.com/trustbloc/orb/pkg/activitypub/resthandler"
	apservice "github.com/trustbloc/orb/pkg/activitypub/service"
	"github.com/trustbloc/orb/pkg/activitypub/service/acceptlist"
	"github.com/trustbloc/orb/pkg/activitypub/service/activityhandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/anchorsynctask"
	apspi "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	apariesstore "github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	apmemstore "github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	activitypubspi "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/allowedorigins/allowedoriginsmgr"
	"github.com/trustbloc/orb/pkg/anchor/allowedorigins/allowedoriginsrest"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/vcresthandler"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/handler/acknowlegement"
	"github.com/trustbloc/orb/pkg/anchor/handler/credential"
	"github.com/trustbloc/orb/pkg/anchor/handler/proof"
	"github.com/trustbloc/orb/pkg/anchor/linkstore"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
	policycfg "github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/inspector"
	policyhandler "github.com/trustbloc/orb/pkg/anchor/witness/policy/resthandler"
	"github.com/trustbloc/orb/pkg/anchor/writer"
	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	ipfscas "github.com/trustbloc/orb/pkg/cas/ipfs"
	"github.com/trustbloc/orb/pkg/cas/resolver"
	"github.com/trustbloc/orb/pkg/config"
	configclient "github.com/trustbloc/orb/pkg/config/client"
	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/orb/pkg/context/opqueue"
	orbpc "github.com/trustbloc/orb/pkg/context/protocol/client"
	orbpcp "github.com/trustbloc/orb/pkg/context/protocol/provider"
	localdiscovery "github.com/trustbloc/orb/pkg/discovery/did/local"
	discoveryclient "github.com/trustbloc/orb/pkg/discovery/endpoint/client"
	discoveryrest "github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
	"github.com/trustbloc/orb/pkg/document/didresolver"
	"github.com/trustbloc/orb/pkg/document/remoteresolver"
	"github.com/trustbloc/orb/pkg/document/resolvehandler"
	"github.com/trustbloc/orb/pkg/document/updatehandler"
	"github.com/trustbloc/orb/pkg/document/updatehandler/decorator"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/document/webresolver"
	"github.com/trustbloc/orb/pkg/healthcheck"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/httpserver/auth/signature"
	"github.com/trustbloc/orb/pkg/httpserver/maintenance"
	"github.com/trustbloc/orb/pkg/nodeinfo"
	"github.com/trustbloc/orb/pkg/observability/loglevels"
	metricsProvider "github.com/trustbloc/orb/pkg/observability/metrics"
	noopmetrics "github.com/trustbloc/orb/pkg/observability/metrics/noop"
	"github.com/trustbloc/orb/pkg/observability/metrics/prometheus"
	"github.com/trustbloc/orb/pkg/observability/tracing"
	"github.com/trustbloc/orb/pkg/observability/tracing/otelamqp"
	"github.com/trustbloc/orb/pkg/observer"
	"github.com/trustbloc/orb/pkg/protocolversion/factoryregistry"
	"github.com/trustbloc/orb/pkg/pubsub/amqp"
	"github.com/trustbloc/orb/pkg/pubsub/mempubsub"
	"github.com/trustbloc/orb/pkg/pubsub/spi"
	"github.com/trustbloc/orb/pkg/resolver/resource"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry"
	"github.com/trustbloc/orb/pkg/resolver/resource/registry/didanchorinfo"
	"github.com/trustbloc/orb/pkg/store"
	anchorlinkstore "github.com/trustbloc/orb/pkg/store/anchorlink"
	"github.com/trustbloc/orb/pkg/store/anchorstatus"
	casstore "github.com/trustbloc/orb/pkg/store/cas"
	didanchorstore "github.com/trustbloc/orb/pkg/store/didanchor"
	"github.com/trustbloc/orb/pkg/store/expiry"
	"github.com/trustbloc/orb/pkg/store/logentry"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
	opstore "github.com/trustbloc/orb/pkg/store/operation"
	unpublishedopstore "github.com/trustbloc/orb/pkg/store/operation/unpublished"
	"github.com/trustbloc/orb/pkg/store/publickey"
	proofstore "github.com/trustbloc/orb/pkg/store/witness"
	"github.com/trustbloc/orb/pkg/store/wrapper"
	"github.com/trustbloc/orb/pkg/taskmgr"
	cryptoutil "github.com/trustbloc/orb/pkg/util"
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/vct"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring/handler"
	logmonitorhandler "github.com/trustbloc/orb/pkg/vct/logmonitoring/resthandler"
	"github.com/trustbloc/orb/pkg/vct/proofmonitoring"
	vcthandler "github.com/trustbloc/orb/pkg/vct/resthandler"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchororigin"
	"github.com/trustbloc/orb/pkg/webcas"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	masterKeyURI = "local-lock://custom/master/key/"

	defaultMaxWitnessDelay                  = 10 * time.Minute
	defaultMaxClockSkew                     = 1 * time.Minute
	defaultWitnessStoreExpiryDelta          = 12 * time.Minute
	defaultProofMonitoringExpiryPeriod      = 1 * time.Hour
	defaultSyncTimeout                      = 1
	defaulthttpSignaturesEnabled            = true
	defaultDidDiscoveryEnabled              = false
	defaultUnpublishedOperationStoreEnabled = false
	defaultIncludeUnpublishedOperations     = false
	defaultIncludePublishedOperations       = false
	defaultResolveFromAnchorOrigin          = false
	defaultVerifyLatestFromAnchorOrigin     = false
	defaultLocalCASReplicateInIPFSEnabled   = false
	defaultDevModeEnabled                   = false
	defaultMaintenanceModeEnabled           = false
	defaultVCTEnabled                       = false
	defaultCasCacheSize                     = 1000
	defaultWebfingerCacheExpiration         = 5 * time.Minute
	defaultWebfingerCacheSize               = 1000

	unpublishedDIDLabel = "uAAA"
)

var logger = log.New("orb-server")

const (
	basePath = "/sidetree/v1"

	baseResolvePath = basePath + "/identifiers"
	baseUpdatePath  = basePath + "/operations"

	activityPubServicesPath = "/services/orb"

	casPath = "/cas"

	kmsKeyType           = kms.ED25519Type
	jsonWebSignature2020 = "JsonWebSignature2020"
	ed25519Signature2020 = "Ed25519Signature2020"

	webKeyStoreKey = "web-key-store"
	vcKidKey       = "vckid"
	httpKidKey     = "httpkid"

	configDBName = "orb-config"
)

type publisherSubscriber interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	PublishWithOpts(topic string, message *message.Message, opts ...spi.Option) error
	IsConnected() bool
	Close() error
}

type keyManager interface {
	Create(kt kms.KeyType, opts ...kms.KeyOpts) (string, interface{}, error)
	Get(keyID string) (interface{}, error)
	ExportPubKeyBytes(keyID string) ([]byte, kms.KeyType, error)
	ImportPrivateKey(privKey interface{}, kt kms.KeyType, opts ...kms.PrivateKeyOpts) (string, interface{}, error)
	HealthCheck() error
}

type crypto interface {
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

type service interface {
	Start()
	Stop()
}

// run starts the HTTP server along with the provided services. The HTTP server is started first and then the services
// are started. When the server is stopped, the services are stopped in reverse order.
func run(srv *httpserver.Server, services ...service) error {
	if err := srv.Start(); err != nil {
		return err
	}

	logger.Info("Started Orb REST service")

	for _, service := range services {
		service.Start()
	}

	logger.Info("Started Orb services")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	// Stop the services in reverse order
	for i := len(services) - 1; i >= 0; i-- {
		services[i].Stop()
	}

	logger.Info("Stopped Orb services")

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

type keyStoreCfg struct {
	URL   string `json:"url,omitempty"`
	KeyID string `json:"keyID,omitempty"`
}

func createKMSAndCrypto(parameters *orbParameters, httpClient *http.Client, s storage.Provider,
	cfg storage.Store, metrics metricsProvider.Metrics,
) (keyManager, crypto, error) {
	switch parameters.kmsParams.kmsType {
	case kmsLocal:
		return createLocalKMS(parameters.kmsParams.secretLockKeyPath, masterKeyURI, s)
	case kmsWeb:
		if strings.Contains(parameters.kmsParams.kmsEndpoint, "keystores") {
			return webkms.New(parameters.kmsParams.kmsEndpoint, httpClient),
				webcrypto.New(parameters.kmsParams.kmsEndpoint, httpClient), nil
		}

		keyStoreCfg := &keyStoreCfg{}

		err := getOrInit(cfg, webKeyStoreKey, &keyStoreCfg, func() (interface{}, error) {
			var err error

			keyStoreCfg.URL, _, err = webkms.CreateKeyStore(httpClient, parameters.kmsParams.kmsEndpoint, uuid.New().String(), "", nil)

			return keyStoreCfg, err
		}, parameters.syncTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("get or init: %w", err)
		}

		keyStoreURL := BuildKMSURL(parameters.kmsParams.kmsEndpoint, keyStoreCfg.URL)

		return webkms.New(keyStoreURL, httpClient), webcrypto.New(keyStoreURL, httpClient), nil
	case kmsAWS:
		region := parameters.kmsParams.kmsRegion

		if strings.Contains(parameters.kmsParams.vcSignActiveKeyID, "arn") {
			var err error

			region, err = getRegion(parameters.kmsParams.vcSignActiveKeyID)
			if err != nil {
				return nil, nil, err
			}
		}

		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &parameters.kmsParams.kmsEndpoint,
			Region:                        aws.String(region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		if err != nil {
			return nil, nil, err
		}

		awsSvc := awssvc.New(awsSession, metrics, parameters.kmsParams.vcSignActiveKeyID)

		return &awsKMSWrapper{service: awsSvc}, awsSvc, nil
	}

	return nil, nil, fmt.Errorf("unsupported kms type: %s", parameters.kmsParams.kmsType)
}

func createLocalKMS(secretLockKeyPath, masterKeyURI string, s storage.Provider) (keyManager, crypto, error) {
	secretLockService, err := prepareKeyLock(secretLockKeyPath)
	if err != nil {
		return nil, nil, err
	}

	// TODO (#1434): Create our own implementation of the KMS storage interface and pass it in here instead of
	//  wrapping the Aries storage provider.
	kmsStore, err := kms.NewAriesProviderWrapper(s)
	if err != nil {
		return nil, nil, fmt.Errorf("create Aries KMS store wrapper: %w", err)
	}

	km, err := localkms.New(masterKeyURI, &kmsProvider{
		storageProvider:   kmsStore,
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

// awsKMSWrapper acts as an adapter that allows the AWS KMS service implementation to be used to implement the
// keyManager and Aries KMS interfaces.
type awsKMSWrapper struct {
	service *awssvc.Service
}

func (a *awsKMSWrapper) Create(kt kms.KeyType, _ ...kms.KeyOpts) (string, interface{}, error) {
	return a.service.Create(kt)
}

func (a *awsKMSWrapper) Get(keyID string) (interface{}, error) {
	return a.service.Get(keyID)
}

func (a *awsKMSWrapper) ExportPubKeyBytes(keyID string) ([]byte, kms.KeyType, error) {
	return a.service.ExportPubKeyBytes(keyID)
}

func (a *awsKMSWrapper) ImportPrivateKey(privKey interface{}, kt kms.KeyType, opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
	return a.service.ImportPrivateKey(privKey, kt, opts...)
}

func (a awsKMSWrapper) HealthCheck() error {
	return a.service.HealthCheck()
}

func createKID(km keyManager, httpSignKeyType bool, parameters *orbParameters, cfg storage.Store) error {
	activeKeyID := &parameters.kmsParams.vcSignActiveKeyID
	kidKey := vcKidKey

	if httpSignKeyType {
		activeKeyID = &parameters.kmsParams.httpSignActiveKeyID
		kidKey = httpKidKey
	}

	keyStoreCfg := &keyStoreCfg{}

	err := getOrInit(cfg, kidKey, keyStoreCfg, func() (interface{}, error) {
		var err error

		keyStoreCfg.KeyID, _, err = km.Create(kmsKeyType)

		return keyStoreCfg, err
	}, parameters.syncTimeout)
	if err != nil {
		return fmt.Errorf("create Key ID: %w", err)
	}

	*activeKeyID = keyStoreCfg.KeyID

	return nil
}

func importPrivateKey(km keyManager, httpSignKeyType bool, parameters *orbParameters, cfg storage.Store) error {
	activeKeyID := &parameters.kmsParams.vcSignActiveKeyID
	privateKeys := parameters.kmsParams.vcSignPrivateKeys
	kidKey := vcKidKey

	if httpSignKeyType {
		activeKeyID = &parameters.kmsParams.httpSignActiveKeyID
		privateKeys = parameters.kmsParams.httpSignPrivateKey
		kidKey = httpKidKey
	}

	return getOrInit(cfg, kidKey, activeKeyID, func() (interface{}, error) {
		for keyID, value := range privateKeys {
			keyBytes, err := base64.RawStdEncoding.DecodeString(value)
			if err != nil {
				return nil, err
			}

			kid, _, err := km.ImportPrivateKey(ed25519.PrivateKey(keyBytes), kms.ED25519, kms.WithKeyID(keyID))
			if err == nil && strings.TrimSpace(kid) == "" {
				return nil, errors.New("import private key: keyID is empty")
			}
		}

		return activeKeyID, nil
	}, parameters.syncTimeout)
}

//nolint:funlen,gocyclo
func startOrbServices(parameters *orbParameters) error {
	if parameters.logLevel != "" {
		setLogLevels(logger, parameters.logLevel)
	}

	mp := newMetricsProvider(parameters)

	metrics := mp.Metrics()

	tracerProvider, err := tracing.Initialize(parameters.observability.tracing.provider,
		parameters.observability.tracing.serviceName, parameters.observability.tracing.collectorURL)
	if err != nil {
		return fmt.Errorf("create tracer: %w", err)
	}

	storeProviders, err := createStoreProviders(parameters, metrics)
	if err != nil {
		return err
	}

	configStore, err := store.Open(storeProviders.provider, configDBName)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	httpClient, err := newHTTPClient(parameters)
	if err != nil {
		return err
	}

	km, cr, err := createKMSAndCrypto(parameters, httpClient, storeProviders.kmsSecretsProvider, configStore, metrics)
	if err != nil {
		return err
	}

	casIRI := mustParseURL(parameters.http.externalEndpoint, casPath)

	coreCASClient, err := newCASClient(parameters, storeProviders.provider, casIRI, metrics)
	if err != nil {
		return err
	}

	didAnchors, err := didanchorstore.New(storeProviders.provider)
	if err != nil {
		return err
	}

	opStore, err := opstore.New(storeProviders.provider, metrics)
	if err != nil {
		return err
	}

	ldStore, err := newLDStoreProvider(storeProviders.provider)
	if err != nil {
		return err
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

	vdrClient := vdr.New(
		vdr.WithVDR(&webVDR{http: httpClient, VDR: vdrweb.New(), useHTTPOpt: useHTTPOpt}),
	)

	err = initKMS(parameters, km, configStore)
	if err != nil {
		return err
	}

	// authTokenManager is used by the REST endpoints to authorize the request.
	authTokenManager, err := auth.NewTokenManager(auth.Config{
		AuthTokensDef: parameters.auth.tokenDefinitions,
		AuthTokens:    parameters.auth.tokens,
	})
	if err != nil {
		return fmt.Errorf("create server Token Manager: %w", err)
	}

	// clientTokenManager is used by the HTTP transport to determine whether an outbound
	// HTTP request should be signed.
	clientTokenManager, err := auth.NewTokenManager(auth.Config{
		AuthTokensDef: parameters.auth.clientTokenDefinitions,
		AuthTokens:    parameters.auth.clientTokens,
	})
	if err != nil {
		return fmt.Errorf("create client Token Manager: %w", err)
	}

	apGetSigner, apPostSigner := getActivityPubSigners(parameters, km, cr)

	publicKeyID, err := url.Parse(parameters.apServiceParams.publicKeyIRI())
	if err != nil {
		return fmt.Errorf("parse public key ID: %w", err)
	}

	httpTransport := transport.New(httpClient, publicKeyID, apGetSigner, apPostSigner, clientTokenManager)

	var endpointClient *discoveryclient.Client

	wfClient := wfclient.New(
		wfclient.WithHTTPClient(httpClient),
		wfclient.WithDIDDomainResolver(func(did string) (string, error) {
			return endpointClient.ResolveDomainForDID(did)
		}),
		wfclient.WithCacheLifetime(defaultWebfingerCacheExpiration), // TODO: Define parameter.
		wfclient.WithCacheSize(defaultWebfingerCacheSize),           // TODO: Define parameter.
	)

	webCASResolver := resolver.NewWebCASResolver(httpTransport, wfClient, webFingerURIScheme)

	var ipfsReader *ipfscas.Client
	var casResolver *resolver.Resolver
	if parameters.cas.ipfsURL != "" {
		ipfsReader = ipfscas.New(parameters.cas.ipfsURL, parameters.cas.ipfsTimeout, defaultCasCacheSize, metrics,
			extendedcasclient.WithCIDVersion(parameters.cas.cidVersion))
		casResolver = resolver.New(coreCASClient, ipfsReader, webCASResolver, metrics)
	} else {
		casResolver = resolver.New(coreCASClient, nil, webCASResolver, metrics)
	}

	generatorRegistry := generator.NewRegistry()

	anchorLinksetBuilder := anchorlinkset.NewBuilder(generatorRegistry)

	graphProviders := &graph.Providers{
		CasResolver:          casResolver,
		CasWriter:            coreCASClient,
		DocLoader:            orbDocumentLoader,
		AnchorLinksetBuilder: anchorLinksetBuilder,
	}

	anchorGraph := graph.New(graphProviders)

	taskMgr := taskmgr.New(configStore, parameters.taskMgrCheckInterval)

	expiryService := expiry.NewService(taskMgr, parameters.dataExpiryCheckInterval)

	var updateDocumentStore *unpublishedopstore.Store
	if parameters.unpublishedOperations.enabled {
		updateDocumentStore, err = unpublishedopstore.New(storeProviders.provider,
			parameters.unpublishedOperations.lifespan, expiryService, metrics)
		if err != nil {
			return fmt.Errorf("failed to create unpublished document store: %w", err)
		}
	}

	originURIs, err := asURIs(parameters.allowedOrigins...)
	if err != nil {
		return fmt.Errorf("invalid anchor origins: %w", err)
	}

	allowedOriginsStore, err := allowedoriginsmgr.New(configStore, originURIs...)
	if err != nil {
		return fmt.Errorf("new allowed origin store: %w", err)
	}

	// get protocol client provider
	pcp, err := getProtocolClientProvider(parameters, coreCASClient, casResolver, opStore,
		storeProviders.provider, updateDocumentStore, anchororigin.New(allowedOriginsStore,
			parameters.allowedOriginsCacheExpiration), metrics)
	if err != nil {
		return fmt.Errorf("failed to create protocol client provider: %w", err)
	}

	pc, err := pcp.ForNamespace(parameters.sidetree.didNamespace)
	if err != nil {
		return fmt.Errorf("failed to get protocol client for namespace [%s]: %w", parameters.sidetree.didNamespace, err)
	}

	pubKeys, signatureSuiteType, err := getPublicKeys(parameters, km)
	if err != nil {
		return err
	}

	externalEndpoint, err := url.Parse(parameters.http.externalEndpoint)
	if err != nil {
		return fmt.Errorf("parse external endpoint: %w", err)
	}

	signingParams := vcsigner.SigningParams{
		VerificationMethod: "did:web:" + externalEndpoint.Host + "#" + parameters.kmsParams.vcSignActiveKeyID,
		Domain:             parameters.anchorCredentialParams.domain,
		SignatureSuite:     signatureSuiteType,
	}

	signingProviders := &vcsigner.Providers{
		KeyManager: km,
		Crypto:     cr,
		DocLoader:  orbDocumentLoader,
		Metrics:    metrics,
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

	alStore, err := anchorlinkstore.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create anchor event store: %s", err.Error())
	}

	witnessProofStore, err := proofstore.New(storeProviders.provider, expiryService, parameters.witnessProof.witnessStoreExpiryPeriod)
	if err != nil {
		return fmt.Errorf("failed to create proof store: %s", err.Error())
	}

	var processorOpts []processor.Option
	if parameters.unpublishedOperations.enabled {
		processorOpts = append(processorOpts, processor.WithUnpublishedOperationStore(updateDocumentStore))
	}

	opProcessor := processor.New(parameters.sidetree.didNamespace, opStore, pc, processorOpts...)

	didAnchoringInfoProvider := didanchorinfo.New(parameters.sidetree.didNamespace, didAnchors, opProcessor)

	// add any additional supported namespaces to resource registry (for now we have just one)
	resourceRegistry := registry.New(registry.WithResourceInfoProvider(didAnchoringInfoProvider))

	apStore, err := createActivityPubStore(storeProviders.provider, parameters.apServiceParams.serviceEndpoint().Path)
	if err != nil {
		return err
	}

	httpSignActivePubKey, httpSignKeyType, err := km.ExportPubKeyBytes(parameters.kmsParams.httpSignActiveKeyID)
	if err != nil {
		return fmt.Errorf("failed to export pub key: %w", err)
	}

	httpSignActivePublicKey, err := getActivityPubPublicKey(httpSignActivePubKey, httpSignKeyType, parameters.apServiceParams)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	var httpSignPubKeys []discoveryrest.PublicKey

	httpSignPubKeys = append(httpSignPubKeys, discoveryrest.PublicKey{
		ID:   parameters.kmsParams.httpSignActiveKeyID,
		Type: httpSignKeyType, Value: httpSignActivePubKey,
	})

	pkStore, err := publickey.New(storeProviders.provider, verifiable.NewVDRKeyResolver(vdrClient).PublicKeyFetcher())
	if err != nil {
		return fmt.Errorf("create public key storage: %w", err)
	}

	publicKeyFetcher := func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return pkStore.GetPublicKey(issuerID, keyID)
	}

	endpointClient, err = discoveryclient.New(orbDocumentLoader,
		&discoveryCAS{resolver: casResolver},
		discoveryclient.WithNamespace(parameters.sidetree.didNamespace),
		discoveryclient.WithHTTPClient(httpClient),
		discoveryclient.WithDIDWebHTTP(parameters.enableDevMode),
		discoveryclient.WithPublicKeyFetcher(publicKeyFetcher),
		discoveryclient.WithVDR(vdrClient),
	)
	if err != nil {
		return fmt.Errorf("new discovery client: %w", err)
	}

	resourceResolver := resource.New(httpClient, ipfsReader, endpointClient)

	apClient := client.New(client.Config{
		CacheSize:       parameters.activityPub.clientCacheSize,
		CacheExpiration: parameters.activityPub.clientCacheExpiration,
	}, httpTransport, publicKeyFetcher, resourceResolver)

	apSigVerifier := getActivityPubVerifier(parameters, km, cr, apClient)

	proofMonitoringSvc, err := proofmonitoring.New(storeProviders.provider, orbDocumentLoader, wfClient,
		httpClient, taskMgr, parameters.vct.proofMonitoringInterval, parameters.requestTokens)
	if err != nil {
		return fmt.Errorf("new VCT monitoring service: %w", err)
	}

	logMonitoringSvc, logMonitorStore, err := newLogMonitoringService(parameters, httpClient, storeProviders.provider)
	if err != nil {
		return err
	}

	taskMgr.RegisterTask("vct-log-consistency-monitor", parameters.vct.logMonitoringInterval, logMonitoringSvc.MonitorLogs)

	policyStore := policycfg.NewPolicyStore(configStore)

	witnessPolicy, err := policy.New(policyStore, parameters.witnessPolicyCacheExpiration)
	if err != nil {
		return fmt.Errorf("failed to create witness policy: %s", err.Error())
	}

	var activityPubService *apservice.Service

	witnessPolicyInspectorProviders := &inspector.Providers{
		AnchorLinkStore: alStore,
		WitnessStore:    witnessProofStore,
		Outbox:          func() inspector.Outbox { return activityPubService.Outbox() },
		WitnessPolicy:   witnessPolicy,
	}

	policyInspector, err := inspector.New(witnessPolicyInspectorProviders, parameters.witnessProof.maxWitnessDelay)
	if err != nil {
		return fmt.Errorf("failed to create witness policy inspector: %s", err.Error())
	}

	anchorEventStatusStore, err := anchorstatus.New(storeProviders.provider, expiryService,
		parameters.witnessProof.maxWitnessDelay, anchorstatus.WithPolicyHandler(policyInspector),
		anchorstatus.WithCheckStatusAfterTime(parameters.anchorStatusInProcessGracePeriod))
	if err != nil {
		return fmt.Errorf("failed to create vc status store: %s", err.Error())
	}

	taskMgr.RegisterTask("anchor-status-monitor", parameters.anchorStatusMonitoringInterval, anchorEventStatusStore.CheckInProcessAnchors)

	pubSub := newPubSub(parameters)

	proofHandler := proof.New(
		&proof.Providers{
			AnchorLinkStore: alStore,
			StatusStore:     anchorEventStatusStore,
			MonitoringSvc:   proofMonitoringSvc,
			DocLoader:       orbDocumentLoader,
			WitnessStore:    witnessProofStore,
			WitnessPolicy:   witnessPolicy,
			Metrics:         metrics,
		},
		pubSub, parameters.dataURIMediaType, parameters.witnessProof.maxClockSkew,
	)

	witness := vct.New(configclient.New(configStore), vcSigner, metrics,
		vct.WithHTTPClient(httpClient),
		vct.WithDocumentLoader(orbDocumentLoader),
		vct.WithAuthReadToken(parameters.requestTokens[vctReadTokenKey]),
		vct.WithAuthWriteToken(parameters.requestTokens[vctWriteTokenKey]),
	)

	logMonitorHandler := handler.New(logMonitorStore, wfClient)

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
		Metrics:                metrics,
		Outbox:                 func() observer.Outbox { return activityPubService.Outbox() },
		HostMetaLinkResolver:   resourceResolver,
		CASResolver:            casResolver,
		DocLoader:              orbDocumentLoader,
		Pkf:                    publicKeyFetcher,
		AnchorLinkStore:        anchorLinkStore,
		AnchorLinksetBuilder:   anchorLinksetBuilder,
		MonitoringSvc:          proofMonitoringSvc,
	}

	obsrv, err := observer.New(parameters.apServiceParams.serviceIRI(), providers,
		observer.WithDiscoveryDomain(parameters.discoveryDomain),
		observer.WithSubscriberPoolSize(parameters.mqParams.observerPoolSize),
		observer.WithProofMonitoringExpiryPeriod(parameters.witnessProof.proofMonitoringExpiryPeriod),
	)
	if err != nil {
		return fmt.Errorf("failed to create observer: %w", err)
	}

	anchorEventHandler := acknowlegement.New(anchorLinkStore)

	err = anchorsynctask.Register(
		anchorsynctask.Config{
			ServiceIRI:     parameters.apServiceParams.serviceIRI(),
			Interval:       parameters.activityPub.anchorSyncPeriod,
			MinActivityAge: parameters.activityPub.anchorSyncMinActivityAge,
		},
		taskMgr, apClient, apStore, storeProviders.provider,
		func() apspi.InboxHandler {
			return activityPubService.InboxHandler()
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register anchor sync task: %w", err)
	}

	apConfig := &apservice.Config{
		ServicePath:              parameters.apServiceParams.serviceEndpoint().Path,
		ServiceIRI:               parameters.apServiceParams.serviceIRI(),
		ServiceEndpointURL:       parameters.apServiceParams.serviceEndpoint(),
		VerifyActorInSignature:   parameters.auth.httpSignaturesEnabled,
		MaxWitnessDelay:          parameters.witnessProof.maxWitnessDelay,
		IRICacheSize:             parameters.activityPub.iriCacheSize,
		IRICacheExpiration:       parameters.activityPub.iriCacheExpiration,
		OutboxSubscriberPoolSize: parameters.mqParams.outboxPoolSize,
		InboxSubscriberPoolSize:  parameters.mqParams.inboxPoolSize,
	}

	activityPubService, err = apservice.New(apConfig,
		apStore, httpTransport, apSigVerifier, pubSub, apClient, resourceResolver, authTokenManager, metrics,
		apspi.WithProofHandler(proofHandler),
		apspi.WithAcceptFollowHandler(logMonitorHandler),
		apspi.WithUndoFollowHandler(logMonitorHandler),
		apspi.WithWitness(witness),
		apspi.WithAnchorEventHandler(credential.New(
			obsrv.Publisher(), casResolver, orbDocumentLoader, parameters.witnessProof.maxWitnessDelay,
			anchorLinkStore, generatorRegistry,
		)),
		apspi.WithInviteWitnessAuth(newAcceptRejectHandler(activityhandler.InviteWitnessType, parameters.auth.inviteWitnessPolicy, configStore)),
		apspi.WithFollowAuth(newAcceptRejectHandler(activityhandler.FollowType, parameters.auth.followPolicy, configStore)),
		apspi.WithAnchorEventAcknowledgementHandler(anchorEventHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	go monitorActivities(activityPubService.Subscribe(), logger)

	vcStore, err := store.Open(storeProviders.provider, "verifiable")
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	anchorWriterProviders := &writer.Providers{
		AnchorGraph:            anchorGraph,
		DidAnchors:             didAnchors,
		AnchorBuilder:          vcBuilder,
		AnchorLinkStore:        alStore,
		AnchorEventStatusStore: anchorEventStatusStore,
		OpProcessor:            opProcessor,
		Outbox:                 activityPubService.Outbox(),
		ProofHandler:           proofHandler,
		Witness:                witness,
		Signer:                 vcSigner,
		MonitoringSvc:          proofMonitoringSvc,
		ActivityStore:          apStore,
		WitnessStore:           witnessProofStore,
		WitnessPolicy:          witnessPolicy,
		WFClient:               wfClient,
		DocumentLoader:         orbDocumentLoader,
		VCStore:                vcStore,
		GeneratorRegistry:      generatorRegistry,
		AnchorLinkBuilder:      anchorLinksetBuilder,
	}

	anchorWriter, err := writer.New(parameters.sidetree.didNamespace,
		parameters.apServiceParams.serviceIRI(),
		parameters.apServiceParams.serviceEndpoint(),
		casIRI,
		parameters.dataURIMediaType,
		anchorWriterProviders,
		obsrv.Publisher(), pubSub,
		parameters.witnessProof.maxWitnessDelay,
		parameters.witnessProof.signWithLocalWitness,
		resourceResolver, parameters.mqParams.anchorLinksetPoolSize,
		metrics)
	if err != nil {
		return fmt.Errorf("failed to create writer: %s", err.Error())
	}

	opQueue, err := opqueue.New(*parameters.opQueueParams, pubSub, storeProviders.provider,
		taskMgr, expiryService, metrics)
	if err != nil {
		return fmt.Errorf("failed to create operation queue: %s", err.Error())
	}

	// create new batch writer
	batchWriter, err := batch.New(parameters.sidetree.didNamespace,
		sidetreecontext.New(pc, anchorWriter, opQueue),
		batch.WithBatchTimeout(parameters.batchWriterTimeout))
	if err != nil {
		return fmt.Errorf("failed to create batch writer: %s", err.Error())
	}

	var didDocHandlerOpts []dochandler.Option

	if parameters.enableDevMode {
		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithDomain("http:"+externalEndpoint.Host))
	} else {
		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithDomain("https:"+externalEndpoint.Host))
	}

	didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithLabel(unpublishedDIDLabel))

	if parameters.unpublishedOperations.enabled {
		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithUnpublishedOperationStore(updateDocumentStore,
			parameters.unpublishedOperations.operationTypes))
	}

	if parameters.verifyLatestFromAnchorOrigin {
		operationDecorator := decorator.New(parameters.sidetree.didNamespace,
			parameters.http.externalEndpoint,
			opProcessor,
			endpointClient,
			remoteresolver.New(httpTransport),
			metrics,
		)

		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithOperationDecorator(operationDecorator))
	}

	didDocHandler := dochandler.New(
		parameters.sidetree.didNamespace,
		parameters.sidetree.didAliases,
		pc,
		batchWriter,
		opProcessor,
		metrics,
		didDocHandlerOpts...,
	)

	apEndpointCfg := &aphandler.Config{
		BasePath:               parameters.apServiceParams.serviceEndpoint().Path,
		ObjectIRI:              parameters.apServiceParams.serviceIRI(),
		ServiceEndpointURL:     parameters.apServiceParams.serviceEndpoint(),
		VerifyActorInSignature: parameters.auth.httpSignaturesEnabled,
		PageSize:               parameters.activityPub.pageSize,
	}

	didDiscovery := localdiscovery.New(parameters.sidetree.didNamespace, obsrv.Publisher(), endpointClient)

	orbResolveHandler := resolvehandler.NewResolveHandler(
		parameters.sidetree.didNamespace,
		didDocHandler,
		didDiscovery,
		parameters.http.externalEndpoint,
		endpointClient,
		remoteresolver.New(httpTransport),
		anchorGraph,
		metrics,
		resolvehandler.WithUnpublishedDIDLabel(unpublishedDIDLabel),
		resolvehandler.WithEnableDIDDiscovery(parameters.didDiscoveryEnabled),
		resolvehandler.WithEnableResolutionFromAnchorOrigin(parameters.resolveFromAnchorOrigin),
	)

	orbDocUpdateHandler := updatehandler.New(didDocHandler, metrics)

	var logEndpoint logEndpoint

	if parameters.enableVCT {
		logEndpoint = witness
	} else {
		logger.Warn("VCT is disabled.")

		logEndpoint = &noOpRetriever{}
	}

	// current external endpoint is always allowed
	allowedDIDWebDomains := []*url.URL{externalEndpoint}

	if len(parameters.allowedDIDWebDomains) > 0 {
		allowedDIDWebDomains = append(allowedDIDWebDomains, parameters.allowedDIDWebDomains...)
	}

	webResolveHandler := webresolver.NewResolveHandler(allowedDIDWebDomains, parameters.sidetree.didNamespace,
		unpublishedDIDLabel, orbResolveHandler, metrics)

	// create discovery rest api
	endpointDiscoveryOp, err := discoveryrest.New(
		&discoveryrest.Config{
			PubKeys:                   pubKeys,
			HTTPSignPubKeys:           httpSignPubKeys,
			ResolutionPath:            baseResolvePath,
			OperationPath:             baseUpdatePath,
			WebCASPath:                casPath,
			DiscoveryDomains:          parameters.discovery.domains,
			DiscoveryMinimumResolvers: parameters.discovery.minimumResolvers,
			ServiceID:                 parameters.apServiceParams.serviceIRI(),
			ServiceEndpointURL:        parameters.apServiceParams.serviceEndpoint(),
		},
		&discoveryrest.Providers{
			ResourceRegistry:     resourceRegistry,
			CAS:                  coreCASClient,
			AnchorLinkStore:      anchorLinkStore,
			WebfingerClient:      wfClient,
			LogEndpointRetriever: logEndpoint,
			WebResolver:          webResolveHandler,
		})
	if err != nil {
		return fmt.Errorf("discovery rest: %w", err)
	}

	var usingMongoDB bool

	if parameters.dbParameters.databaseType == databaseTypeMongoDBOption {
		usingMongoDB = true
	}

	if !usingMongoDB {
		logger.Warn("The NodeInfo service is not optimized for storage providers other than MongoDB. " +
			"With a large database, it may consume lots of memory. " +
			"See https://github.com/trustbloc/orb/issues/797 for more information.")
	}

	nodeInfoService := nodeinfo.NewService(parameters.apServiceParams.serviceEndpoint(),
		parameters.nodeInfoRefreshInterval, apStore, usingMongoDB)

	handlers := make([]restcommon.HTTPHandler, 0)

	didResolveHandler := didresolver.NewResolveHandler(orbResolveHandler, webResolveHandler)

	var sidetreeOperationsHandler restcommon.HTTPHandler
	var sidetreeResolutionHandler restcommon.HTTPHandler
	var activityInboxHandler restcommon.HTTPHandler

	sidetreeOperationsHandler = auth.NewHandlerWrapper(
		diddochandler.NewUpdateHandler(baseUpdatePath, orbDocUpdateHandler, pc, metrics),
		authTokenManager,
	)

	sidetreeResolutionHandler = signature.NewHandlerWrapper(diddochandler.NewResolveHandler(baseResolvePath, didResolveHandler, metrics),
		&aphandler.Config{
			ObjectIRI:              parameters.apServiceParams.serviceIRI(),
			VerifyActorInSignature: parameters.auth.httpSignaturesEnabled,
			PageSize:               parameters.activityPub.pageSize,
		},
		apStore, apSigVerifier, authTokenManager,
	)

	activityInboxHandler = activityPubService.InboxHTTPHandler()

	if parameters.enableMaintenanceMode {
		sidetreeOperationsHandler = maintenance.NewMaintenanceWrapper(sidetreeOperationsHandler)
		sidetreeResolutionHandler = maintenance.NewMaintenanceWrapper(sidetreeResolutionHandler)
		activityInboxHandler = maintenance.NewMaintenanceWrapper(activityInboxHandler)
	}

	handlers = append(handlers,
		sidetreeOperationsHandler,
		sidetreeResolutionHandler,
		activityInboxHandler,
		aphandler.NewServices(apEndpointCfg, apStore, httpSignActivePublicKey, authTokenManager),
		aphandler.NewPublicKeys(apEndpointCfg, apStore, httpSignActivePublicKey, authTokenManager),
		aphandler.NewFollowers(apEndpointCfg, apStore, apSigVerifier, authTokenManager),
		aphandler.NewFollowing(apEndpointCfg, apStore, apSigVerifier, authTokenManager),
		aphandler.NewOutbox(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending, authTokenManager),
		aphandler.NewInbox(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending, authTokenManager),
		aphandler.NewWitnesses(apEndpointCfg, apStore, apSigVerifier, authTokenManager),
		aphandler.NewWitnessing(apEndpointCfg, apStore, apSigVerifier, authTokenManager),
		aphandler.NewLiked(apEndpointCfg, apStore, apSigVerifier, authTokenManager),
		aphandler.NewLikes(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending, authTokenManager),
		aphandler.NewShares(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending, authTokenManager),
		aphandler.NewPostOutbox(apEndpointCfg, activityPubService.Outbox(), apStore, apSigVerifier, authTokenManager),
		aphandler.NewActivity(apEndpointCfg, apStore, apSigVerifier, activitypubspi.SortAscending, authTokenManager),
		webcas.New(
			&aphandler.Config{
				ObjectIRI:              parameters.apServiceParams.serviceIRI(),
				VerifyActorInSignature: parameters.auth.httpSignaturesEnabled,
				PageSize:               parameters.activityPub.pageSize,
			},
			apStore, apSigVerifier, coreCASClient, authTokenManager,
		),
		auth.NewHandlerWrapper(policyhandler.New(policyStore), authTokenManager),
		auth.NewHandlerWrapper(policyhandler.NewRetriever(policyStore), authTokenManager),
		auth.NewHandlerWrapper(logmonitorhandler.NewUpdateHandler(logMonitorStore), authTokenManager),
		auth.NewHandlerWrapper(logmonitorhandler.NewRetriever(logMonitorStore), authTokenManager),
		auth.NewHandlerWrapper(vcthandler.New(configStore, logMonitorStore), authTokenManager),
		auth.NewHandlerWrapper(vcthandler.NewRetriever(configStore), authTokenManager),
		auth.NewHandlerWrapper(nodeinfo.NewHandler(nodeinfo.V2_0, nodeInfoService), authTokenManager),
		auth.NewHandlerWrapper(nodeinfo.NewHandler(nodeinfo.V2_1, nodeInfoService), authTokenManager),
		auth.NewHandlerWrapper(vcresthandler.New(vcStore), authTokenManager),
		auth.NewHandlerWrapper(allowedoriginsrest.NewWriter(allowedOriginsStore), authTokenManager),
		auth.NewHandlerWrapper(allowedoriginsrest.NewReader(allowedOriginsStore), authTokenManager),
		auth.NewHandlerWrapper(loglevels.NewWriteHandler(), authTokenManager),
		auth.NewHandlerWrapper(loglevels.NewReadHandler(), authTokenManager),
	)

	handlers = append(handlers, endpointDiscoveryOp.GetRESTHandlers()...)

	if parameters.auth.followPolicy == acceptListPolicy || parameters.auth.inviteWitnessPolicy == acceptListPolicy {
		// Register endpoints to manage the 'accept list'.
		handlers = append(handlers,
			auth.NewHandlerWrapper(aphandler.NewAcceptListWriter(apEndpointCfg, acceptlist.NewManager(configStore)), authTokenManager),
			auth.NewHandlerWrapper(aphandler.NewAcceptListReader(apEndpointCfg, acceptlist.NewManager(configStore)), authTokenManager),
		)
	}

	handlers = append(handlers, healthcheck.NewHandler(pubSub, logEndpoint, storeProviders.provider, km, parameters.enableMaintenanceMode))

	httpServer := httpserver.New(
		parameters.http.hostURL,
		httpserver.WithCertFile(parameters.http.tls.serveCertPath),
		httpserver.WithKeyFile(parameters.http.tls.serveKeyPath),
		httpserver.WithServerIdleTimeout(parameters.http.serverIdleTimeout),
		httpserver.WithServerReadHeaderTimeout(parameters.http.serverReadHeaderTimeout),
		httpserver.WithTracingEnabled(parameters.observability.tracing.enabled),
		httpserver.WithTracingServiceName(parameters.observability.tracing.serviceName),
		httpserver.WithHandlers(handlers...),
	)

	err = run(httpServer, activityPubService, opQueue, obsrv, batchWriter, taskMgr,
		nodeInfoService, newMPLifecycleWrapper(mp), tracerProvider)
	if err != nil {
		return err
	}

	if err := pubSub.Close(); err != nil {
		logger.Warn("Error closing publisher/subscriber", log.WithError(err))
	}

	return nil
}

func newHTTPClient(parameters *orbParameters) (*http.Client, error) {
	rootCAs, err := tlsutil.GetCertPool(parameters.http.tls.systemCertPool, parameters.http.tls.caCerts)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}

	if parameters.enableDevMode {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint: gosec
		}
	}

	var httpTransport http.RoundTripper = &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   parameters.http.dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2000,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if parameters.observability.tracing.enabled {
		httpTransport = otelhttp.NewTransport(httpTransport)
	}

	return &http.Client{
		Timeout:   parameters.http.timeout,
		Transport: httpTransport,
	}, nil
}

func newCASClient(parameters *orbParameters, p dbProvider, casIRI *url.URL,
	metrics metricsProvider.Metrics,
) (extendedcasclient.Client, error) {
	switch {
	case strings.EqualFold(parameters.cas.casType, "ipfs"):
		logger.Info("Initializing Orb CAS with IPFS.")

		return ipfscas.New(parameters.cas.ipfsURL, parameters.cas.ipfsTimeout, defaultCasCacheSize, metrics,
			extendedcasclient.WithCIDVersion(parameters.cas.cidVersion)), nil
	case strings.EqualFold(parameters.cas.casType, "local"):
		logger.Info("Initializing Orb CAS with local storage provider.")

		if parameters.cas.localCASReplicateInIPFSEnabled {
			logger.Info("Local CAS writes will be replicated in IPFS.")

			return casstore.New(p, casIRI.String(),
				ipfscas.New(parameters.cas.ipfsURL, parameters.cas.ipfsTimeout, defaultCasCacheSize, metrics,
					extendedcasclient.WithCIDVersion(parameters.cas.cidVersion)),
				metrics, defaultCasCacheSize, extendedcasclient.WithCIDVersion(parameters.cas.cidVersion))
		} else {
			return casstore.New(p, casIRI.String(), nil,
				metrics, defaultCasCacheSize, extendedcasclient.WithCIDVersion(parameters.cas.cidVersion))
		}

	default:
		return nil, fmt.Errorf("%s is not a valid CAS type. It must be either local or ipfs", parameters.cas.casType)
	}
}

func newPubSub(parameters *orbParameters) publisherSubscriber {
	mqParams := parameters.mqParams

	if mqParams.endpoint == "" {
		return mempubsub.New(mempubsub.DefaultConfig())
	}

	var ps publisherSubscriber = amqp.New(amqp.Config{
		URI:                       mqParams.endpoint,
		MaxConnectionChannels:     mqParams.maxConnectionChannels,
		PublisherChannelPoolSize:  mqParams.publisherChannelPoolSize,
		PublisherConfirmDelivery:  mqParams.publisherConfirmDelivery,
		MaxConnectRetries:         mqParams.maxConnectRetries,
		MaxRedeliveryAttempts:     mqParams.maxRedeliveryAttempts,
		RedeliveryMultiplier:      mqParams.redeliveryMultiplier,
		RedeliveryInitialInterval: mqParams.redeliveryInitialInterval,
		MaxRedeliveryInterval:     mqParams.maxRedeliveryInterval,
	})

	if parameters.observability.tracing.enabled {
		ps = otelamqp.New(ps)
	}

	return ps
}

func getPublicKeys(parameters *orbParameters, km keyManager) ([]discoveryrest.PublicKey, string, error) {
	pubKeys := make([]discoveryrest.PublicKey, 0)

	vcActivePubKey, vcActiveKeyType, err := km.ExportPubKeyBytes(parameters.kmsParams.vcSignActiveKeyID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to export pub key: %w", err)
	}

	pubKeys = append(pubKeys, discoveryrest.PublicKey{
		ID:   parameters.kmsParams.vcSignActiveKeyID,
		Type: vcActiveKeyType, Value: vcActivePubKey,
	})

	if len(parameters.kmsParams.vcSignPrivateKeys) > 0 {
		for keyID := range parameters.kmsParams.vcSignPrivateKeys {
			pubKey, pubKeyType, e := km.ExportPubKeyBytes(keyID)
			if e != nil {
				return nil, "", fmt.Errorf("failed to export pub key: %w", e)
			}

			pubKeys = append(pubKeys, discoveryrest.PublicKey{
				ID:   keyID,
				Type: pubKeyType, Value: pubKey,
			})
		}
	}

	if len(parameters.kmsParams.vcSignKeysID) > 0 {
		for _, keyID := range parameters.kmsParams.vcSignKeysID {
			pubKey, pubKeyType, e := km.ExportPubKeyBytes(keyID)
			if e != nil {
				return nil, "", fmt.Errorf("failed to export pub key: %w", e)
			}

			pubKeys = append(pubKeys, discoveryrest.PublicKey{
				ID:   keyID,
				Type: pubKeyType, Value: pubKey,
			})
		}
	}

	signatureSuiteType := jsonWebSignature2020

	if vcActiveKeyType == kms.ED25519 {
		signatureSuiteType = ed25519Signature2020
	}

	return pubKeys, signatureSuiteType, nil
}

func newLogMonitoringService(parameters *orbParameters,
	httpClient *http.Client, dbp dbProvider,
) (*logmonitoring.Client, *logmonitor.Store, error) {
	logMonitorStore, err := logmonitor.New(dbp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create log monitor store: %w", err)
	}

	logMonitoringOpts := []logmonitoring.Option{
		logmonitoring.WithMaxTreeSize(parameters.vct.logMonitoringTreeSize),
		logmonitoring.WithMaxGetEntriesRange(parameters.vct.logMonitoringGetEntriesRange),
	}

	if parameters.vct.logEntriesStoreEnabled {
		logEntryStore, e := logentry.New(dbp)
		if e != nil {
			return nil, nil, fmt.Errorf("failed to create log entries store: %w", e)
		}

		logMonitoringOpts = append(logMonitoringOpts,
			logmonitoring.WithLogEntriesStoreEnabled(true),
			logmonitoring.WithLogEntriesStore(logEntryStore))
	}

	logMonitoringSvc, err := logmonitoring.New(logMonitorStore, httpClient, parameters.requestTokens,
		logMonitoringOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("new VCT consistency monitoring service: %w", err)
	}

	return logMonitoringSvc, logMonitorStore, nil
}

func initKMS(parameters *orbParameters, km keyManager, configStore storage.Store) error {
	if parameters.kmsParams.vcSignActiveKeyID == "" {
		if err := createKID(km, false, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	if parameters.kmsParams.httpSignActiveKeyID == "" {
		if err := createKID(km, true, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	if parameters.kmsParams.vcSignActiveKeyID != "" && len(parameters.kmsParams.vcSignPrivateKeys) > 0 {
		if err := importPrivateKey(km, false, parameters, configStore); err != nil {
			return fmt.Errorf("import kid: %w", err)
		}
	}

	if parameters.kmsParams.httpSignActiveKeyID != "" && len(parameters.kmsParams.httpSignPrivateKey) > 0 {
		if err := importPrivateKey(km, true, parameters, configStore); err != nil {
			return fmt.Errorf("import kid: %w", err)
		}
	}

	return nil
}

func newLDStoreProvider(dbp dbProvider) (*ldStoreProvider, error) {
	ldStorageProvider := cachedstore.NewProvider(dbp, ariesmemstorage.NewProvider())

	contextStore, err := ldstore.NewContextStore(ldStorageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(ldStorageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	return &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}, nil
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, casResolver common.CASResolver,
	opStore common.OperationStore, provider storage.Provider, unpublishedOpStore *unpublishedopstore.Store,
	allowedOriginsValidator operationparser.ObjectValidator, metrics metricsProvider.Metrics,
) (*orbpcp.ClientProvider, error) {
	sidetreeCfg := config.Sidetree{
		MethodContext:                           parameters.methodContext,
		EnableBase:                              parameters.baseEnabled,
		UnpublishedOpStore:                      unpublishedOpStore,
		UnpublishedOperationStoreOperationTypes: parameters.unpublishedOperations.operationTypes,
		IncludeUnpublishedOperations:            parameters.unpublishedOperations.includeUnpublished,
		IncludePublishedOperations:              parameters.unpublishedOperations.includePublished,
		AllowedOriginsValidator:                 allowedOriginsValidator,
	}

	r := factoryregistry.New()

	var protocolVersions []protocol.Version
	for _, version := range parameters.sidetree.protocolVersions {
		pv, err := r.CreateProtocolVersion(version, casClient, casResolver, opStore, provider, &sidetreeCfg, metrics)
		if err != nil {
			return nil, fmt.Errorf("error creating protocol version [%s]: %w", version, err)
		}

		protocolVersions = append(protocolVersions, pv)
	}

	pcp := orbpcp.New()

	var pcOpts []orbpc.Option
	if parameters.sidetree.currentProtocolVersion != "" {
		pcOpts = append(pcOpts, orbpc.WithCurrentProtocolVersion(parameters.sidetree.currentProtocolVersion))
	}

	pc, err := orbpc.New(protocolVersions, pcOpts...)
	if err != nil {
		return nil, err
	}

	pcp.Add(parameters.sidetree.didNamespace, pc)

	return pcp, nil
}

func createActivityPubStore(storageProvider dbProvider, serviceEndpoint string) (activitypubspi.Store, error) {
	switch strings.ToLower(storageProvider.DBType()) {
	case databaseTypeMongoDBOption:
		apStore, err := apariesstore.New(serviceEndpoint, storageProvider, true)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aries storage provider for ActivityPub: %w", err)
		}

		return apStore, nil

	case databaseTypeCouchDBOption:
		apStore, err := apariesstore.New(serviceEndpoint, storageProvider, false)
		if err != nil {
			return nil, fmt.Errorf("failed to create Aries storage provider for ActivityPub: %w", err)
		}

		return apStore, nil

	default:
		return apmemstore.New(serviceEndpoint), nil
	}
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
	storageProvider   kms.Store
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() kms.Store {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

type provider interface {
	OpenStore(name string) (storage.Store, error)
	SetStoreConfig(name string, config storage.StoreConfiguration) error
	GetStoreConfig(name string) (storage.StoreConfiguration, error)
	GetOpenStores() []storage.Store
	Close() error
	Ping() error
}

type dbProvider interface {
	provider

	DBType() string
}

type mongoDBProvider interface {
	provider

	CreateCustomIndexes(storeName string, model ...mongo.IndexModel) error
}

type storageProvider struct {
	provider
	dbType string
}

func (p *storageProvider) DBType() string {
	return p.dbType
}

type mongoDBStorageProvider struct {
	mongoDBProvider
	dbType string
}

func (p *mongoDBStorageProvider) DBType() string {
	return p.dbType
}

type storageProviders struct {
	provider           dbProvider
	kmsSecretsProvider storage.Provider
}

func createStoreProviders(parameters *orbParameters, metrics metricsProvider.Metrics) (*storageProviders, error) {
	var edgeServiceProvs storageProviders

	switch {
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		edgeServiceProvs.provider = &storageProvider{ariesmemstorage.NewProvider(), databaseTypeMemOption}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		couchDBProvider, err := ariescouchdbstorage.NewProvider(
			parameters.dbParameters.databaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariescouchdbstorage.WithLogger(logger.Sugar()))
		if err != nil {
			return &storageProviders{}, err
		}

		edgeServiceProvs.provider = &storageProvider{
			wrapper.NewProvider(couchDBProvider, "CouchDB", metrics),
			databaseTypeCouchDBOption,
		}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger.Sugar()),
			ariesmongodbstorage.WithTimeout(parameters.dbParameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider: %w", err)
		}

		edgeServiceProvs.provider = &mongoDBStorageProvider{
			wrapper.NewMongoDBProvider(mongoDBProvider, metrics),
			databaseTypeMongoDBOption,
		}

	default:
		return &storageProviders{}, fmt.Errorf("database type not set to a valid type." +
			" run start --help to see the available options")
	}

	if parameters.kmsParams.kmsType != kmsLocal {
		return &edgeServiceProvs, nil
	}

	switch {
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeMemOption):
		edgeServiceProvs.kmsSecretsProvider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeCouchDBOption):
		couchDBProvider, err := ariescouchdbstorage.NewProvider(
			parameters.kmsParams.kmsSecretsDatabaseURL,
			ariescouchdbstorage.WithDBPrefix(parameters.kmsParams.kmsSecretsDatabasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}

		edgeServiceProvs.kmsSecretsProvider = wrapper.NewProvider(couchDBProvider, "CouchDB", metrics)
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.kmsParams.kmsSecretsDatabaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.kmsParams.kmsSecretsDatabasePrefix),
			ariesmongodbstorage.WithLogger(logger.Sugar()),
			ariesmongodbstorage.WithTimeout(parameters.dbParameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider: %w", err)
		}

		edgeServiceProvs.kmsSecretsProvider = wrapper.NewProvider(mongoDBProvider, "MongoDB", metrics)
	default:
		return &storageProviders{}, fmt.Errorf("key database type not set to a valid type." +
			" run start --help to see the available options")
	}

	return &edgeServiceProvs, nil
}

func getOrInit(cfg storage.Store, keyID string, v interface{}, initFn func() (interface{}, error), timeout uint64) error {
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
			return json.Unmarshal(src, v)
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
		return fmt.Errorf("put config value for %q: %w", keyID, err)
	}

	logger.Debug("Stored KMS key", logfields.WithKeyID(keyID), logfields.WithValue(src))

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

func getActivityPubPublicKey(pubKeyBytes []byte, keyType kms.KeyType, apServiceParams *apServiceParams) (*vocab.PublicKeyType, error) {
	publicKeyID, err := url.Parse(apServiceParams.publicKeyIRI())
	if err != nil {
		return nil, fmt.Errorf("parse public key ID: %w", err)
	}

	if util.IsDID(publicKeyID.String()) {
		return vocab.NewPublicKey(vocab.WithID(publicKeyID)), nil
	}

	pemBytes, err := cryptoutil.EncodePublicKeyToPEM(pubKeyBytes, keyType)
	if err != nil {
		return nil, fmt.Errorf("encode public key to PEM: %w", err)
	}

	return vocab.NewPublicKey(
		vocab.WithID(publicKeyID),
		vocab.WithOwner(apServiceParams.serviceIRI()),
		vocab.WithPublicKeyPem(string(pemBytes)),
	), nil
}

type signer interface {
	SignRequest(pubKeyID string, req *http.Request) error
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

func getActivityPubSigners(parameters *orbParameters, km keyManager, cr crypto) (getSigner, postSigner signer) {
	if parameters.auth.httpSignaturesEnabled {
		getSigner = httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), cr, km, parameters.kmsParams.httpSignActiveKeyID)
		postSigner = httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), cr, km, parameters.kmsParams.httpSignActiveKeyID)
	} else {
		getSigner = &transport.NoOpSigner{}
		postSigner = &transport.NoOpSigner{}
	}

	return
}

type logEndpoint interface {
	GetLogEndpoint() (string, error)
	HealthCheck() error
}

type noOpRetriever struct{}

func (r *noOpRetriever) GetLogEndpoint() (string, error) {
	return "", vct.ErrDisabled
}

func (r *noOpRetriever) HealthCheck() error {
	return vct.ErrDisabled
}

func getActivityPubVerifier(parameters *orbParameters, km keyManager, cr crypto, apClient *client.Client) signatureVerifier {
	if parameters.auth.httpSignaturesEnabled {
		return httpsig.NewVerifier(apClient, cr, km)
	}

	logger.Warn("HTTP signature verification for ActivityPub is disabled.")

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

func createJSONLDDocumentLoader(ldStore *ldStoreProvider, httpClient *http.Client, providerURLs []string) (jsonld.DocumentLoader, error) {
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

func newAcceptRejectHandler(targetType string, p acceptRejectPolicy, configStore storage.Store) apspi.ActorAuth {
	switch p {
	case acceptListPolicy:
		return activityhandler.NewAcceptListAuthHandler(targetType, acceptlist.NewManager(configStore))
	default:
		return &activityhandler.AcceptAllActorsAuth{}
	}
}

type activityLogger interface {
	Debug(msg string, fields ...zap.Field)
	Warn(msg string, fields ...zap.Field)
}

func monitorActivities(activityChan <-chan *vocab.ActivityType, l activityLogger) {
	logger.Info("Activity monitor started.")

	for activity := range activityChan {
		switch {
		case activity.Type().IsAny(vocab.TypeReject):
			// Log this as a warning since one of our activities was rejected by another server.
			l.Warn("Received activity",
				logfields.WithActivityID(activity.ID()), logfields.WithActivityType(activity.Type().String()),
				logfields.WithActorIRI(activity.Actor()))
		default:
			l.Debug("Received activity",
				logfields.WithActivityID(activity.ID()), logfields.WithActivityType(activity.Type().String()),
				logfields.WithActorIRI(activity.Actor()))
		}
	}

	logger.Info("Activity monitor stopped.")
}

func asURIs(strs ...string) ([]*url.URL, error) {
	uris := make([]*url.URL, len(strs))

	for i, str := range strs {
		uri, err := url.Parse(str)
		if err != nil {
			return nil, fmt.Errorf("invalid URI: %s: %w", str, err)
		}

		uris[i] = uri
	}

	return uris, nil
}

func newMetricsProvider(parameters *orbParameters) metricsProvider.Provider {
	switch parameters.observability.metrics.providerName {
	case "prometheus":
		metricsHTTPServer := httpserver.New(
			parameters.observability.metrics.url, httpserver.WithHandlers(prometheus.NewHandler()),
		)

		return prometheus.NewProvider(metricsHTTPServer)
	default:
		return noopmetrics.NewProvider()
	}
}

func getRegion(keyURI string) (string, error) {
	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
	re1 := regexp.MustCompile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):`)

	r := re1.FindStringSubmatch(keyURI)

	const subStringCount = 3

	if len(r) != subStringCount {
		return "", fmt.Errorf("extracting region from URI failed")
	}

	return r[2], nil
}

type mpLifecycleWrapper struct {
	mp metricsProvider.Provider
}

func newMPLifecycleWrapper(mp metricsProvider.Provider) *mpLifecycleWrapper {
	return &mpLifecycleWrapper{mp: mp}
}

func (w *mpLifecycleWrapper) Start() {
	if err := w.mp.Create(); err != nil {
		panic(fmt.Errorf("create metrics provider: %w", err))
	}
}

func (w *mpLifecycleWrapper) Stop() {
	if err := w.mp.Destroy(); err != nil {
		logger.Warn("Failed to stop metrics provider", log.WithError(err))
	}
}
