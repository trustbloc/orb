/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/uuid"
	ariescouchdbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	ariesmongodbstorage "github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
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
	awssvc "github.com/trustbloc/kms/pkg/aws"
	casapi "github.com/trustbloc/sidetree-core-go/pkg/api/cas"
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
	"github.com/trustbloc/orb/pkg/activitypub/service/anchorsynctask"
	apspi "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	apariesstore "github.com/trustbloc/orb/pkg/activitypub/store/ariesstore"
	apmemstore "github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	activitypubspi "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/vcresthandler"
	"github.com/trustbloc/orb/pkg/anchor/builder"
	"github.com/trustbloc/orb/pkg/anchor/graph"
	"github.com/trustbloc/orb/pkg/anchor/handler/acknowlegement"
	"github.com/trustbloc/orb/pkg/anchor/handler/credential"
	"github.com/trustbloc/orb/pkg/anchor/handler/proof"
	"github.com/trustbloc/orb/pkg/anchor/linkstore"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy"
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
	"github.com/trustbloc/orb/pkg/vcsigner"
	"github.com/trustbloc/orb/pkg/vct"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring/handler"
	"github.com/trustbloc/orb/pkg/vct/proofmonitoring"
	vcthandler "github.com/trustbloc/orb/pkg/vct/resthandler"
	"github.com/trustbloc/orb/pkg/webcas"
	wfclient "github.com/trustbloc/orb/pkg/webfinger/client"
)

const (
	masterKeyURI = "local-lock://custom/master/key/"

	defaultMaxWitnessDelay                  = 10 * time.Minute
	defaultWitnessStoreExpiryDelta          = 12 * time.Minute
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
	defaultCasCacheSize                     = 1000

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
)

type pubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...spi.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	IsConnected() error
	Close() error
}

type keyManager interface {
	Create(kt kms.KeyType) (string, interface{}, error)
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

	logger.Infof("Started Orb REST service")

	for _, service := range services {
		service.Start()
	}

	logger.Infof("Started Orb services")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	// Stop the services in reverse order
	for i := len(services) - 1; i >= 0; i-- {
		services[i].Stop()
	}

	logger.Infof("Stopped Orb services")

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

			logger.Debugf("Orb parameters: %+v", parameters)

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
	store storage.Provider, cfg storage.Store) (keyManager, crypto, error) {
	switch parameters.kmsParams.kmsType {
	case kmsLocal:
		secretLockService, err := prepareKeyLock(parameters.kmsParams.secretLockKeyPath)
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
	case kmsWeb:
		if strings.Contains(parameters.kmsParams.kmsEndpoint, "keystores") {
			return webkms.New(parameters.kmsParams.kmsEndpoint, client),
				webcrypto.New(parameters.kmsParams.kmsEndpoint, client), nil
		}

		var keystoreURL string

		err := getOrInit(cfg, webKeyStoreKey, &keystoreURL, func() (interface{}, error) {
			location, _, err := webkms.CreateKeyStore(client, parameters.kmsParams.kmsEndpoint, uuid.New().String(), "", nil)

			return location, err
		}, parameters.syncTimeout)
		if err != nil {
			return nil, nil, fmt.Errorf("get or init: %w", err)
		}

		keystoreURL = BuildKMSURL(parameters.kmsParams.kmsEndpoint, keystoreURL)

		return webkms.New(keystoreURL, client), webcrypto.New(keystoreURL, client), nil
	case kmsAWS:
		region, err := getRegion(parameters.kmsParams.vcSignActiveKeyID)
		if err != nil {
			return nil, nil, err
		}

		awsSession, err := session.NewSession(&aws.Config{
			Endpoint:                      &parameters.kmsParams.kmsEndpoint,
			Region:                        aws.String(region),
			CredentialsChainVerboseErrors: aws.Bool(true),
		})
		if err != nil {
			return nil, nil, err
		}

		awsSvc := awssvc.New(awsSession, metrics.Get())

		return awsSvc, awsSvc, nil
	}

	return nil, nil, fmt.Errorf("unsupported kms type: %s", parameters.kmsParams.kmsType)
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

func createKID(km keyManager, httpSignKeyType bool, parameters *orbParameters, cfg storage.Store) error {
	activeKeyID := &parameters.kmsParams.vcSignActiveKeyID
	kidKey := vcKidKey

	if httpSignKeyType {
		activeKeyID = &parameters.kmsParams.httpSignActiveKeyID
		kidKey = httpKidKey
	}

	return getOrInit(cfg, kidKey, activeKeyID, func() (interface{}, error) {
		keyID, _, err := km.Create(kmsKeyType)

		return keyID, err
	}, parameters.syncTimeout)
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

			keyID, _, err := km.ImportPrivateKey(ed25519.PrivateKey(keyBytes), kms.ED25519, kms.WithKeyID(keyID))
			if err == nil && strings.TrimSpace(keyID) == "" {
				return nil, errors.New("import private key: keyID is empty")
			}
		}
		return activeKeyID, nil
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
		MaxIdleConns:          2000,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
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

	opStore, err := opstore.New(storeProviders.provider, metrics.Get())
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

	if parameters.kmsParams.vcSignActiveKeyID == "" {
		if err = createKID(km, false, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	if parameters.kmsParams.httpSignActiveKeyID == "" {
		if err = createKID(km, true, parameters, configStore); err != nil {
			return fmt.Errorf("create kid: %w", err)
		}
	}

	if parameters.kmsParams.vcSignActiveKeyID != "" && len(parameters.kmsParams.vcSignPrivateKeys) > 0 {
		if err = importPrivateKey(km, false, parameters, configStore); err != nil {
			return fmt.Errorf("import kid: %w", err)
		}
	}

	if parameters.kmsParams.httpSignActiveKeyID != "" && len(parameters.kmsParams.httpSignPrivateKey) > 0 {
		if err = importPrivateKey(km, true, parameters, configStore); err != nil {
			return fmt.Errorf("import kid: %w", err)
		}
	}

	apServicePublicKeyIRI := mustParseURL(parameters.externalEndpoint,
		fmt.Sprintf("%s/keys/%s", activityPubServicesPath, aphandler.MainKeyID))

	// authTokenManager is used by the REST endpoints to authorize the request.
	authTokenManager, err := auth.NewTokenManager(auth.Config{
		AuthTokensDef: parameters.authTokenDefinitions,
		AuthTokens:    parameters.authTokens,
	})
	if err != nil {
		return fmt.Errorf("create server Token Manager: %w", err)
	}

	// clientTokenManager is used by the HTTP transport to determine whether an outbound
	// HTTP request should be signed.
	clientTokenManager, err := auth.NewTokenManager(auth.Config{
		AuthTokensDef: parameters.clientAuthTokenDefinitions,
		AuthTokens:    parameters.clientAuthTokens,
	})
	if err != nil {
		return fmt.Errorf("create client Token Manager: %w", err)
	}

	apGetSigner, apPostSigner := getActivityPubSigners(parameters, km, cr)

	t := transport.New(httpClient, apServicePublicKeyIRI, apGetSigner, apPostSigner, clientTokenManager)

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
	if parameters.unpublishedOperationStoreEnabled {
		updateDocumentStore, err = unpublishedopstore.New(storeProviders.provider,
			parameters.unpublishedOperationLifespan, expiryService, metrics.Get())
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

	vcActivePubKey, vcActiveKeyType, err := km.ExportPubKeyBytes(parameters.kmsParams.vcSignActiveKeyID)
	if err != nil {
		return fmt.Errorf("failed to export pub key: %w", err)
	}

	signatureSuiteType := jsonWebSignature2020

	if vcActiveKeyType == kms.ED25519 {
		signatureSuiteType = ed25519Signature2020
	}

	signingParams := vcsigner.SigningParams{
		VerificationMethod: "did:web:" + u.Host + "#" + parameters.kmsParams.vcSignActiveKeyID,
		Domain:             parameters.anchorCredentialParams.domain,
		SignatureSuite:     signatureSuiteType,
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

	alStore, err := anchorlinkstore.New(storeProviders.provider, orbDocumentLoader)
	if err != nil {
		return fmt.Errorf("failed to create anchor event store: %s", err.Error())
	}

	witnessProofStore, err := proofstore.New(storeProviders.provider, expiryService, parameters.witnessStoreExpiryPeriod)
	if err != nil {
		return fmt.Errorf("failed to create proof store: %s", err.Error())
	}

	var processorOpts []processor.Option
	if parameters.unpublishedOperationStoreEnabled {
		processorOpts = append(processorOpts, processor.WithUnpublishedOperationStore(updateDocumentStore))
	}

	opProcessor := processor.New(parameters.didNamespace, opStore, pc, processorOpts...)

	didAnchoringInfoProvider := didanchorinfo.New(parameters.didNamespace, didAnchors, opProcessor)

	// add any additional supported namespaces to resource registry (for now we have just one)
	resourceRegistry := registry.New(registry.WithResourceInfoProvider(didAnchoringInfoProvider))
	logger.Debugf("started resource registry: %+v", resourceRegistry)

	apServiceIRI := mustParseURL(parameters.externalEndpoint, activityPubServicesPath)

	var pubSub pubSub

	mqParams := parameters.mqParams

	if mqParams.endpoint != "" {
		pubSub = amqp.New(amqp.Config{
			URI:                        mqParams.endpoint,
			MaxConnectionSubscriptions: mqParams.maxConnectionSubscriptions,
			PublisherChannelPoolSize:   mqParams.publisherChannelPoolSize,
			MaxConnectRetries:          mqParams.maxConnectRetries,
			MaxRedeliveryAttempts:      mqParams.maxRedeliveryAttempts,
			RedeliveryMultiplier:       mqParams.redeliveryMultiplier,
			RedeliveryInitialInterval:  mqParams.redeliveryInitialInterval,
			MaxRedeliveryInterval:      mqParams.maxRedeliveryInterval,
		})
	} else {
		pubSub = mempubsub.New(mempubsub.DefaultConfig())
	}

	apConfig := &apservice.Config{
		ServiceEndpoint:          activityPubServicesPath,
		ServiceIRI:               apServiceIRI,
		VerifyActorInSignature:   parameters.httpSignaturesEnabled,
		MaxWitnessDelay:          parameters.maxWitnessDelay,
		IRICacheSize:             parameters.apIRICacheSize,
		IRICacheExpiration:       parameters.apIRICacheExpiration,
		OutboxSubscriberPoolSize: parameters.mqParams.outboxPoolSize,
		InboxSubscriberPoolSize:  parameters.mqParams.inboxPoolSize,
	}

	apStore, err := createActivityPubStore(storeProviders.provider, apConfig.ServiceEndpoint)
	if err != nil {
		return err
	}

	pubKeys := make([]discoveryrest.PublicKey, 0)

	pubKeys = append(pubKeys, discoveryrest.PublicKey{ID: parameters.kmsParams.vcSignActiveKeyID,
		Type: vcActiveKeyType, Value: vcActivePubKey})

	if len(parameters.kmsParams.vcSignPrivateKeys) > 0 {
		for keyID := range parameters.kmsParams.vcSignPrivateKeys {
			pubKey, pubKeyType, err := km.ExportPubKeyBytes(keyID)
			if err != nil {
				return fmt.Errorf("failed to export pub key: %w", err)
			}

			pubKeys = append(pubKeys, discoveryrest.PublicKey{ID: keyID,
				Type: pubKeyType, Value: pubKey})
		}
	}

	if len(parameters.kmsParams.vcSignKeysID) > 0 {
		for _, keyID := range parameters.kmsParams.vcSignKeysID {
			pubKey, pubKeyType, err := km.ExportPubKeyBytes(keyID)
			if err != nil {
				return fmt.Errorf("failed to export pub key: %w", err)
			}

			pubKeys = append(pubKeys, discoveryrest.PublicKey{ID: keyID,
				Type: pubKeyType, Value: pubKey})
		}
	}

	httpSignActivePubKey, httpSignKeyType, err := km.ExportPubKeyBytes(parameters.kmsParams.httpSignActiveKeyID)
	if err != nil {
		return fmt.Errorf("failed to export pub key: %w", err)
	}

	httpSignActivePublicKey, err := getActivityPubPublicKey(httpSignActivePubKey, httpSignKeyType, apServiceIRI, apServicePublicKeyIRI)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	apClient := client.New(client.Config{
		CacheSize:       parameters.apClientCacheSize,
		CacheExpiration: parameters.apClientCacheExpiration,
	}, t)

	apSigVerifier := getActivityPubVerifier(parameters, km, cr, apClient)

	proofMonitoringSvc, err := proofmonitoring.New(storeProviders.provider, orbDocumentLoader, wfClient,
		httpClient, taskMgr, parameters.vctProofMonitoringInterval, parameters.requestTokens)
	if err != nil {
		return fmt.Errorf("new VCT monitoring service: %w", err)
	}

	logMonitorStore, err := logmonitor.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("failed to create log monitor store: %w", err)
	}

	logMonitoringOpts := []logmonitoring.Option{
		logmonitoring.WithMaxTreeSize(parameters.vctLogMonitoringTreeSize),
		logmonitoring.WithMaxGetEntriesRange(parameters.vctLogMonitoringGetEntriesRange),
	}

	if parameters.vctLogEntriesStoreEnabled {
		logEntryStore, err := logentry.New(storeProviders.provider)
		if err != nil {
			return fmt.Errorf("failed to create log entries store: %w", err)
		}

		logMonitoringOpts = append(logMonitoringOpts,
			logmonitoring.WithLogEntriesStore(logEntryStore))
	}

	logMonitoringSvc, err := logmonitoring.New(logMonitorStore, httpClient, parameters.requestTokens,
		logMonitoringOpts...)
	if err != nil {
		return fmt.Errorf("new VCT consistency monitoring service: %w", err)
	}

	taskMgr.RegisterTask("vct-log-consistency-monitor", parameters.vctLogMonitoringInterval, logMonitoringSvc.MonitorLogs)

	witnessPolicy, err := policy.New(configStore, parameters.witnessPolicyCacheExpiration)
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

	policyInspector, err := inspector.New(witnessPolicyInspectorProviders, parameters.maxWitnessDelay)
	if err != nil {
		return fmt.Errorf("failed to create witness policy inspector: %s", err.Error())
	}

	anchorEventStatusStore, err := anchorstatus.New(storeProviders.provider, expiryService,
		parameters.maxWitnessDelay, anchorstatus.WithPolicyHandler(policyInspector),
		anchorstatus.WithCheckStatusAfterTime(parameters.anchorStatusInProcessGracePeriod))
	if err != nil {
		return fmt.Errorf("failed to create vc status store: %s", err.Error())
	}

	taskMgr.RegisterTask("anchor-status-monitor", parameters.anchorStatusMonitoringInterval, anchorEventStatusStore.CheckInProcessAnchors)

	proofHandler := proof.New(
		&proof.Providers{
			AnchorLinkStore: alStore,
			StatusStore:     anchorEventStatusStore,
			MonitoringSvc:   proofMonitoringSvc,
			DocLoader:       orbDocumentLoader,
			WitnessStore:    witnessProofStore,
			WitnessPolicy:   witnessPolicy,
			Metrics:         metrics.Get(),
		},
		pubSub, parameters.dataURIMediaType)

	logEndpointRetriever := configclient.New(configStore)

	witness := vct.New(logEndpointRetriever, vcSigner, metrics.Get(),
		vct.WithHTTPClient(httpClient),
		vct.WithDocumentLoader(orbDocumentLoader),
		vct.WithAuthReadToken(parameters.requestTokens[vctReadTokenKey]),
		vct.WithAuthWriteToken(parameters.requestTokens[vctWriteTokenKey]),
	)

	resourceResolver := resource.New(httpClient, ipfsReader)

	logMonitorHandler := handler.New(logMonitorStore, wfClient)

	anchorLinkStore, err := linkstore.New(storeProviders.provider)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}

	pkStore, err := publickey.New(storeProviders.provider, verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher())
	if err != nil {
		return fmt.Errorf("create public key storage: %w", err)
	}

	publicKeyFetcher := func(issuerID, keyID string) (*verifier.PublicKey, error) {
		return pkStore.GetPublicKey(issuerID, keyID)
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
		Pkf:                    publicKeyFetcher,
		AnchorLinkStore:        anchorLinkStore,
	}

	observer, err := observer.New(apConfig.ServiceIRI, providers,
		observer.WithDiscoveryDomain(parameters.discoveryDomain),
		observer.WithSubscriberPoolSize(parameters.mqParams.observerPoolSize),
	)
	if err != nil {
		return fmt.Errorf("failed to create observer: %w", err)
	}

	anchorEventHandler := acknowlegement.New(anchorLinkStore)

	err = anchorsynctask.Register(
		anchorsynctask.Config{
			ServiceIRI:     apServiceIRI,
			Interval:       parameters.anchorSyncPeriod,
			MinActivityAge: parameters.anchorSyncMinActivityAge,
		},
		taskMgr, apClient, apStore, storeProviders.provider,
		func() apspi.InboxHandler {
			return activityPubService.InboxHandler()
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register anchor sync task: %w", err)
	}

	activityPubService, err = apservice.New(apConfig,
		apStore, t, apSigVerifier, pubSub, apClient, resourceResolver, authTokenManager, metrics.Get(),
		apspi.WithProofHandler(proofHandler),
		apspi.WithAcceptFollowHandler(logMonitorHandler),
		apspi.WithUndoFollowHandler(logMonitorHandler),
		apspi.WithWitness(witness),
		apspi.WithAnchorEventHandler(credential.New(
			observer.Publisher(), casResolver, orbDocumentLoader, proofMonitoringSvc, parameters.maxWitnessDelay, anchorLinkStore,
		)),
		apspi.WithInviteWitnessAuth(NewAcceptRejectHandler(activityhandler.InviteWitnessType, parameters.inviteWitnessAuthPolicy, configStore)),
		apspi.WithFollowAuth(NewAcceptRejectHandler(activityhandler.FollowType, parameters.followAuthPolicy, configStore)),
		apspi.WithAnchorEventAcknowledgementHandler(anchorEventHandler),
	)
	if err != nil {
		return fmt.Errorf("failed to create ActivityPub service: %s", err.Error())
	}

	go monitorActivities(activityPubService.Subscribe(), logger)

	vcStore, err := storeProviders.provider.OpenStore("verifiable")
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
	}

	anchorWriter, err := writer.New(parameters.didNamespace,
		apServiceIRI, casIRI,
		parameters.dataURIMediaType,
		anchorWriterProviders,
		observer.Publisher(), pubSub,
		parameters.maxWitnessDelay,
		parameters.signWithLocalWitness,
		resourceResolver,
		metrics.Get())
	if err != nil {
		return fmt.Errorf("failed to create writer: %s", err.Error())
	}

	opQueue, err := opqueue.New(*parameters.opQueueParams, pubSub, storeProviders.provider, taskMgr,
		expiryService, metrics.Get())
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

	var didDocHandlerOpts []dochandler.Option
	didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithDomain("https:"+u.Host))
	didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithLabel(unpublishedDIDLabel))

	if parameters.unpublishedOperationStoreEnabled {
		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithUnpublishedOperationStore(updateDocumentStore, parameters.unpublishedOperationStoreOperationTypes))
	}

	endpointClient, err := discoveryclient.New(orbDocumentLoader,
		&discoveryCAS{resolver: casResolver},
		discoveryclient.WithNamespace(parameters.didNamespace),
		discoveryclient.WithHTTPClient(httpClient),
		discoveryclient.WithDIDWebHTTP(parameters.enableDevMode),
		discoveryclient.WithPublicKeyFetcher(publicKeyFetcher),
	)

	if parameters.verifyLatestFromAnchorOrigin {
		operationDecorator := decorator.New(parameters.didNamespace,
			parameters.externalEndpoint,
			opProcessor,
			endpointClient,
			remoteresolver.New(t),
			metrics.Get(),
		)

		didDocHandlerOpts = append(didDocHandlerOpts, dochandler.WithOperationDecorator(operationDecorator))
	}

	didDocHandler := dochandler.New(
		parameters.didNamespace,
		parameters.didAliases,
		pc,
		batchWriter,
		opProcessor,
		metrics.Get(),
		didDocHandlerOpts...,
	)

	apEndpointCfg := &aphandler.Config{
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

	didDiscovery := localdiscovery.New(parameters.didNamespace, observer.Publisher(), endpointClient)

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
			PubKeys:                   pubKeys,
			ResolutionPath:            baseResolvePath,
			OperationPath:             baseUpdatePath,
			WebCASPath:                casPath,
			BaseURL:                   parameters.externalEndpoint,
			DiscoveryDomains:          parameters.discoveryDomains,
			DiscoveryMinimumResolvers: parameters.discoveryMinimumResolvers,
		},
		&discoveryrest.Providers{
			ResourceRegistry:     resourceRegistry,
			CAS:                  coreCASClient,
			AnchorLinkStore:      anchorLinkStore,
			WebfingerClient:      wfClient,
			LogEndpointRetriever: logEndpointRetriever,
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
		auth.NewHandlerWrapper(diddochandler.NewUpdateHandler(baseUpdatePath, orbDocUpdateHandler, pc, metrics.Get()), authTokenManager),
		signature.NewHandlerWrapper(diddochandler.NewResolveHandler(baseResolvePath, orbDocResolveHandler, metrics.Get()),
			&aphandler.Config{
				ObjectIRI:              apServiceIRI,
				VerifyActorInSignature: parameters.httpSignaturesEnabled,
				PageSize:               parameters.activityPubPageSize,
			},
			apStore, apSigVerifier, authTokenManager,
		),
		activityPubService.InboxHTTPHandler(),
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
				ObjectIRI:              apServiceIRI,
				VerifyActorInSignature: parameters.httpSignaturesEnabled,
				PageSize:               parameters.activityPubPageSize,
			},
			apStore, apSigVerifier, coreCASClient, authTokenManager,
		),
		auth.NewHandlerWrapper(policyhandler.New(configStore), authTokenManager),
		auth.NewHandlerWrapper(policyhandler.NewRetriever(configStore), authTokenManager),
		auth.NewHandlerWrapper(vcthandler.New(configStore, logMonitorStore), authTokenManager),
		auth.NewHandlerWrapper(vcthandler.NewRetriever(configStore), authTokenManager),
		auth.NewHandlerWrapper(nodeinfo.NewHandler(nodeinfo.V2_0, nodeInfoService, nodeInfoLogger), authTokenManager),
		auth.NewHandlerWrapper(nodeinfo.NewHandler(nodeinfo.V2_1, nodeInfoService, nodeInfoLogger), authTokenManager),
		auth.NewHandlerWrapper(vcresthandler.New(vcStore), authTokenManager),
	)

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	for _, handler := range ldrest.New(ldsvc.New(ldStore)).GetRESTHandlers() {
		handlers = append(handlers, auth.NewHandlerWrapper(&httpHandler{handler}, authTokenManager))
	}

	if parameters.followAuthPolicy == acceptListPolicy || parameters.inviteWitnessAuthPolicy == acceptListPolicy {
		// Register endpoints to manage the 'accept list'.
		handlers = append(handlers, auth.NewHandlerWrapper(
			aphandler.NewAcceptListWriter(apEndpointCfg, acceptlist.NewManager(configStore)), authTokenManager),
		)
		handlers = append(handlers, auth.NewHandlerWrapper(
			aphandler.NewAcceptListReader(apEndpointCfg, acceptlist.NewManager(configStore)), authTokenManager),
		)
	}

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsParams.serveCertPath,
		parameters.tlsParams.serveKeyPath,
		parameters.serverIdleTimeout,
		pubSub,
		witness,
		storeProviders.provider,
		km,
		handlers...,
	)

	if parameters.hostMetricsURL != "" {
		metricsHttpServer := httpserver.New(
			parameters.hostMetricsURL, "", "", parameters.serverIdleTimeout,
			pubSub, witness, storeProviders.provider, km, metrics.NewHandler(),
		)

		err = metricsHttpServer.Start()
		if err != nil {
			return fmt.Errorf("start metrics HTTP server at %s: %w", parameters.hostMetricsURL, err)
		}
	}

	err = run(httpServer, activityPubService, opQueue, observer, batchWriter, taskMgr, nodeInfoService)
	if err != nil {
		return err
	}

	if err := pubSub.Close(); err != nil {
		logger.Warnf("Error closing publisher/subscriber: %s", err)
	}

	return nil
}

func getProtocolClientProvider(parameters *orbParameters, casClient casapi.Client, casResolver common.CASResolver,
	opStore common.OperationStore, provider storage.Provider,
	unpublishedOpStore *unpublishedopstore.Store) (*orbpcp.ClientProvider, error) {

	sidetreeCfg := config.Sidetree{
		MethodContext:                           parameters.methodContext,
		EnableBase:                              parameters.baseEnabled,
		AnchorOrigins:                           parameters.allowedOrigins,
		UnpublishedOpStore:                      unpublishedOpStore,
		UnpublishedOperationStoreOperationTypes: parameters.unpublishedOperationStoreOperationTypes,
		IncludeUnpublishedOperations:            parameters.includeUnpublishedOperations,
		IncludePublishedOperations:              parameters.includePublishedOperations,
	}

	registry := factoryregistry.New()

	var protocolVersions []protocol.Version
	for _, version := range parameters.sidetreeProtocolVersions {
		pv, err := registry.CreateProtocolVersion(version, casClient, casResolver, opStore, provider, &sidetreeCfg)
		if err != nil {
			return nil, fmt.Errorf("error creating protocol version [%s]: %s", version, err)
		}

		protocolVersions = append(protocolVersions, pv)
	}

	pcp := orbpcp.New()

	var pcOpts []orbpc.Option
	if parameters.currentSidetreeProtocolVersion != "" {
		pcOpts = append(pcOpts, orbpc.WithCurrentProtocolVersion(parameters.currentSidetreeProtocolVersion))
	}

	pc, err := orbpc.New(protocolVersions, pcOpts...)
	if err != nil {
		return nil, err
	}

	pcp.Add(parameters.didNamespace, pc)

	return pcp, nil
}

func createActivityPubStore(storageProvider *storageProvider,
	serviceEndpoint string) (activitypubspi.Store, error) {
	switch strings.ToLower(storageProvider.dbType) {
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
	storageProvider   storage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
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

type storageProvider struct {
	provider
	dbType string
}

type storageProviders struct {
	provider           *storageProvider
	kmsSecretsProvider storage.Provider
}

//nolint: gocyclo
func createStoreProviders(parameters *orbParameters) (*storageProviders, error) {
	var edgeServiceProvs storageProviders

	switch { //nolint: dupl
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMemOption):
		edgeServiceProvs.provider = &storageProvider{ariesmemstorage.NewProvider(), databaseTypeMemOption}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeCouchDBOption):
		couchDBProvider, err :=
			ariescouchdbstorage.NewProvider(parameters.dbParameters.databaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
				ariescouchdbstorage.WithLogger(logger))
		if err != nil {
			return &storageProviders{}, err
		}

		edgeServiceProvs.provider = &storageProvider{wrapper.NewProvider(couchDBProvider, "CouchDB"),
			databaseTypeCouchDBOption}
	case strings.EqualFold(parameters.dbParameters.databaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.dbParameters.databaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.dbParameters.databasePrefix),
			ariesmongodbstorage.WithLogger(logger),
			ariesmongodbstorage.WithTimeout(parameters.databaseTimeout))
		if err != nil {
			return nil, fmt.Errorf("create MongoDB storage provider: %w", err)
		}

		edgeServiceProvs.provider = &storageProvider{wrapper.NewProvider(mongoDBProvider, "MongoDB"),
			databaseTypeMongoDBOption}

	default:
		return &storageProviders{}, fmt.Errorf("database type not set to a valid type." +
			" run start --help to see the available options")
	}

	if parameters.kmsParams.kmsType != kmsLocal {
		return &edgeServiceProvs, nil
	}

	switch { //nolint: dupl
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeMemOption):
		edgeServiceProvs.kmsSecretsProvider = ariesmemstorage.NewProvider()
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeCouchDBOption):
		couchDBProvider, err :=
			ariescouchdbstorage.NewProvider(parameters.kmsParams.kmsSecretsDatabaseURL,
				ariescouchdbstorage.WithDBPrefix(parameters.kmsParams.kmsSecretsDatabasePrefix))
		if err != nil {
			return &storageProviders{}, err
		}

		edgeServiceProvs.kmsSecretsProvider = wrapper.NewProvider(couchDBProvider, "CouchDB")
	case strings.EqualFold(parameters.kmsParams.kmsSecretsDatabaseType, databaseTypeMongoDBOption):
		mongoDBProvider, err := ariesmongodbstorage.NewProvider(parameters.kmsParams.kmsSecretsDatabaseURL,
			ariesmongodbstorage.WithDBPrefix(parameters.kmsParams.kmsSecretsDatabasePrefix),
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

func getActivityPubPublicKey(pubKeyBytes []byte, keyType kms.KeyType, apServiceIRI,
	apServicePublicKeyIRI *url.URL) (*vocab.PublicKeyType, error) {

	pemKeyType := ""
	keyBytes := pubKeyBytes

	switch {
	case keyType == kms.ED25519:
		pemKeyType = "Ed25519"
	case keyType == kms.ECDSAP256IEEEP1363 || keyType == kms.ECDSAP256DER:
		pemKeyType = "P-256"
	case keyType == kms.ECDSAP384IEEEP1363 || keyType == kms.ECDSAP384DER:
		pemKeyType = "P-384"
	case keyType == kms.ECDSAP521IEEEP1363 || keyType == kms.ECDSAP521DER:
		pemKeyType = "P-521"
	}

	if keyType == kms.ECDSAP256DER || keyType == kms.ECDSAP384DER || keyType == kms.ECDSAP521DER {
		curveMap := map[string]elliptic.Curve{
			"P-256": elliptic.P256(),
			"P-384": elliptic.P384(),
			"P-521": elliptic.P521(),
		}

		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return nil, err
		}

		keyBytes = elliptic.Marshal(curveMap[pemKeyType], key.(*ecdsa.PublicKey).X, key.(*ecdsa.PublicKey).Y)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  pemKeyType,
		Bytes: keyBytes,
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

func getActivityPubSigners(parameters *orbParameters, km keyManager,
	cr crypto) (getSigner signer, postSigner signer) {
	if parameters.httpSignaturesEnabled {
		getSigner = httpsig.NewSigner(httpsig.DefaultGetSignerConfig(), cr, km, parameters.kmsParams.httpSignActiveKeyID)
		postSigner = httpsig.NewSigner(httpsig.DefaultPostSignerConfig(), cr, km, parameters.kmsParams.httpSignActiveKeyID)
	} else {
		getSigner = &transport.NoOpSigner{}
		postSigner = &transport.NoOpSigner{}
	}

	return
}

func getActivityPubVerifier(parameters *orbParameters, km keyManager,
	cr crypto, apClient *client.Client) signatureVerifier {
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

type activityLogger interface {
	Debugf(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
}

func monitorActivities(activityChan <-chan *vocab.ActivityType, l activityLogger) {
	logger.Infof("Activity monitor started.")

	for activity := range activityChan {
		switch {
		case activity.Type().IsAny(vocab.TypeReject):
			// Log this as a warning since one of our activities was rejected by another server.
			l.Warnf("Received activity [%s] of type %s from [%s]",
				activity.ID(), activity.Type(), activity.Actor())
		default:
			l.Debugf("Received activity [%s] of type %s from [%s]",
				activity.ID(), activity.Type(), activity.Actor())
		}
	}

	logger.Infof("Activity monitor stopped.")
}
