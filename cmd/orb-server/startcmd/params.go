/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/pkg/httpserver/auth"
)

const (
	defaultBatchWriterTimeout           = 60000 * time.Millisecond
	defaultDiscoveryMinimumResolvers    = 1
	defaultActivityPubPageSize          = 50
	defaultNodeInfoRefreshInterval      = 15 * time.Second
	defaultIPFSTimeout                  = 20 * time.Second
	defaultDatabaseTimeout              = 10 * time.Second
	defaultUnpublishedOperationLifespan = time.Minute * 5
	defaultTaskMgrCheckInterval         = 10 * time.Second
	defaultDataExpiryCheckInterval      = time.Minute
	mqDefaultMaxConnectionSubscriptions = 1000

	defaultFollowAuthType        = acceptAllPolicy
	defaultInviteWitnessAuthType = acceptAllPolicy

	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the orb-server instance on. Format: HostName:Port."
	hostURLEnvKey        = "ORB_HOST_URL"

	hostMetricsURLFlagName      = "host-metrics-url"
	hostMetricsURLFlagShorthand = "M"
	hostMetricsURLFlagUsage     = "URL that exposes the metrics endpoint. Format: HostName:Port."
	hostMetricsURLEnvKey        = "ORB_HOST_METRICS_URL"

	syncTimeoutFlagName  = "sync-timeout"
	syncTimeoutEnvKey    = "ORB_SYNC_TIMEOUT"
	syncTimeoutFlagUsage = "Total time in seconds to resolve config values." +
		" Alternatively, this can be set with the following environment variable: " + syncTimeoutEnvKey

	vctURLFlagName  = "vct-url"
	vctURLFlagUsage = "Verifiable credential transparency URL."
	vctURLEnvKey    = "ORB_VCT_URL"

	kmsStoreEndpointFlagName  = "kms-store-endpoint"
	kmsStoreEndpointEnvKey    = "ORB_KMS_STORE_ENDPOINT"
	kmsStoreEndpointFlagUsage = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsStoreEndpointEnvKey

	kmsEndpointFlagName  = "kms-endpoint"
	kmsEndpointEnvKey    = "ORB_KMS_ENDPOINT"
	kmsEndpointFlagUsage = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	keyIDFlagName  = "key-id"
	keyIDEnvKey    = "ORB_KEY_ID"
	keyIDFlagUsage = "Key ID (ED25519Type)." +
		" Alternatively, this can be set with the following environment variable: " + keyIDEnvKey

	privateKeyFlagName  = "private-key"
	privateKeyEnvKey    = "ORB_PRIVATE_KEY"
	privateKeyFlagUsage = "Private Key base64 (ED25519Type)." +
		" Alternatively, this can be set with the following environment variable: " + privateKeyEnvKey

	secretLockKeyPathFlagName  = "secret-lock-key-path"
	secretLockKeyPathEnvKey    = "ORB_SECRET_LOCK_KEY_PATH"
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey

	externalEndpointFlagName      = "external-endpoint"
	externalEndpointFlagShorthand = "e"
	externalEndpointFlagUsage     = "External endpoint that clients use to invoke services." +
		" This endpoint is used to generate IDs of anchor credentials and ActivityPub objects and" +
		" should be resolvable by external clients. Format: HostName[:Port]."
	externalEndpointEnvKey = "ORB_EXTERNAL_ENDPOINT"

	discoveryDomainFlagName  = "discovery-domain"
	discoveryDomainFlagUsage = "Discovery domain for this domain." + " Format: HostName"
	discoveryDomainEnvKey    = "ORB_DISCOVERY_DOMAIN"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ORB_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ORB_TLS_CACERTS"

	tlsCertificateFlagName      = "tls-certificate"
	tlsCertificateFlagShorthand = "y"
	tlsCertificateFlagUsage     = "TLS certificate for ORB server. " + commonEnvVarUsageText + tlsCertificateLEnvKey
	tlsCertificateLEnvKey       = "ORB_TLS_CERTIFICATE"

	tlsKeyFlagName      = "tls-key"
	tlsKeyFlagShorthand = "x"
	tlsKeyFlagUsage     = "TLS key for ORB server. " + commonEnvVarUsageText + tlsKeyEnvKey
	tlsKeyEnvKey        = "ORB_TLS_KEY"

	didNamespaceFlagName      = "did-namespace"
	didNamespaceFlagShorthand = "n"
	didNamespaceFlagUsage     = "DID Namespace." + commonEnvVarUsageText + didNamespaceEnvKey
	didNamespaceEnvKey        = "DID_NAMESPACE"

	didAliasesFlagName      = "did-aliases"
	didAliasesEnvKey        = "DID_ALIASES"
	didAliasesFlagShorthand = "a"
	didAliasesFlagUsage     = "Aliases for this did method. " + commonEnvVarUsageText + didAliasesEnvKey

	casTypeFlagName      = "cas-type"
	casTypeFlagShorthand = "c"
	casTypeEnvKey        = "CAS_TYPE"
	casTypeFlagUsage     = "The type of the Content Addressable Storage (CAS). " +
		"Supported options: local, ipfs. For local, the storage provider specified by " + databaseTypeFlagName +
		" will be used. For ipfs, the node specified by " + ipfsURLFlagName +
		" will be used. This is a required parameter. " + commonEnvVarUsageText + casTypeEnvKey

	ipfsURLFlagName      = "ipfs-url"
	ipfsURLFlagShorthand = "r"
	ipfsURLEnvKey        = "IPFS_URL"
	ipfsURLFlagUsage     = "Enables IPFS support. If set, this Orb server will use the node at the given URL. " +
		"To use the public ipfs.io node, set this to https://ipfs.io (or http://ipfs.io). If using ipfs.io, " +
		"then the CAS type flag must be set to local since the ipfs.io node is read-only. " +
		"If the URL doesn't include a scheme, then HTTP will be used by default. " + commonEnvVarUsageText + ipfsURLEnvKey

	localCASReplicateInIPFSFlagName  = "replicate-local-cas-writes-in-ipfs"
	localCASReplicateInIPFSEnvKey    = "REPLICATE_LOCAL_CAS_WRITES_IN_IPFS"
	localCASReplicateInIPFSFlagUsage = "If enabled, writes to the local CAS will also be " +
		"replicated in IPFS. This setting only takes effect if this server has both a local CAS and IPFS enabled. " +
		"If the IPFS node is set to ipfs.io, then this setting will be disabled since ipfs.io does not support " +
		"writes. Supported options: false, true. Defaults to false if not set. " + commonEnvVarUsageText + localCASReplicateInIPFSEnvKey

	mqURLFlagName      = "mq-url"
	mqURLFlagShorthand = "q"
	mqURLEnvKey        = "MQ_URL"
	mqURLFlagUsage     = "The URL of the message broker. " + commonEnvVarUsageText + mqURLEnvKey

	mqOpPoolFlagName      = "mq-op-pool"
	mqOpPoolFlagShorthand = "O"
	mqOpPoolEnvKey        = "MQ_OP_POOL"
	mqOpPoolFlagUsage     = "The size of the operation queue subscriber pool. If <=1 then a pool will not be created. " +
		commonEnvVarUsageText + mqOpPoolEnvKey

	mqObserverPoolFlagName      = "mq-observer-pool"
	mqObserverPoolFlagShorthand = "B"
	mqObserverPoolEnvKey        = "MQ_OBSERVER_POOL"
	mqObserverPoolFlagUsage     = "The size of the observer queue subscriber pool. If not specified then the default size will be used. " +
		commonEnvVarUsageText + mqObserverPoolEnvKey

	mqMaxConnectionSubscriptionsFlagName      = "mq-max-connection-subscription"
	mqMaxConnectionSubscriptionsFlagShorthand = "C"
	mqMaxConnectionSubscriptionsEnvKey        = "MQ_MAX_CONNECTION_SUBSCRIPTIONS"
	mqMaxConnectionSubscriptionsFlagUsage     = "The maximum number of subscriptions per connection. " +
		commonEnvVarUsageText + mqMaxConnectionSubscriptionsEnvKey

	cidVersionFlagName  = "cid-version"
	cidVersionEnvKey    = "CID_VERSION"
	cidVersionFlagUsage = "The version of the CID format to use for generating CIDs. " +
		"Supported options: 0, 1. If not set, defaults to 1." + commonEnvVarUsageText + cidVersionEnvKey

	batchWriterTimeoutFlagName      = "batch-writer-timeout"
	batchWriterTimeoutFlagShorthand = "b"
	batchWriterTimeoutEnvKey        = "BATCH_WRITER_TIMEOUT"
	batchWriterTimeoutFlagUsage     = "Maximum time (in millisecond) in-between cutting batches." +
		commonEnvVarUsageText + batchWriterTimeoutEnvKey

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "DATABASE_TYPE"
	databaseTypeFlagShorthand = "t"
	databaseTypeFlagUsage     = "The type of database to use for everything except key storage. " +
		"Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + databaseTypeEnvKey

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "DATABASE_URL"
	databaseURLFlagShorthand = "v"
	databaseURLFlagUsage     = "The URL (or connection string) of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText + databaseURLEnvKey

	databasePrefixFlagName  = "database-prefix"
	databasePrefixEnvKey    = "DATABASE_PREFIX"
	databasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving underlying databases. " +
		commonEnvVarUsageText + databasePrefixEnvKey

	// Linter gosec flags these as "potential hardcoded credentials". They are not, hence the nolint annotations.
	kmsSecretsDatabaseTypeFlagName      = "kms-secrets-database-type" //nolint: gosec
	kmsSecretsDatabaseTypeEnvKey        = "KMSSECRETS_DATABASE_TYPE"  //nolint: gosec
	kmsSecretsDatabaseTypeFlagShorthand = "k"
	kmsSecretsDatabaseTypeFlagUsage     = "The type of database to use for storage of KMS secrets. " +
		"Supported options: mem, couchdb, mongodb. " + commonEnvVarUsageText + kmsSecretsDatabaseTypeEnvKey

	kmsSecretsDatabaseURLFlagName      = "kms-secrets-database-url" //nolint: gosec
	kmsSecretsDatabaseURLEnvKey        = "KMSSECRETS_DATABASE_URL"  //nolint: gosec
	kmsSecretsDatabaseURLFlagShorthand = "s"
	kmsSecretsDatabaseURLFlagUsage     = "The URL (or connection string) of the database. Not needed if using memstore. For CouchDB, " +
		"include the username:password@ text if required. " +
		commonEnvVarUsageText + databaseURLEnvKey

	kmsSecretsDatabasePrefixFlagName  = "kms-secrets-database-prefix" //nolint: gosec
	kmsSecretsDatabasePrefixEnvKey    = "KMSSECRETS_DATABASE_PREFIX"  //nolint: gosec
	kmsSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving " +
		"the underlying KMS secrets database. " + commonEnvVarUsageText + kmsSecretsDatabasePrefixEnvKey

	databaseTimeoutFlagName  = "database-timeout"
	databaseTimeoutEnvKey    = "DATABASE_TIMEOUT"
	databaseTimeoutFlagUsage = "The timeout for database requests. For example, '30s' for a 30 second timeout. " +
		"Currently this setting only applies if you're using MongoDB. " +
		commonEnvVarUsageText + databaseTimeoutEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMongoDBOption = "mongodb"

	anchorCredentialIssuerFlagName      = "anchor-credential-issuer"
	anchorCredentialIssuerEnvKey        = "ANCHOR_CREDENTIAL_ISSUER"
	anchorCredentialIssuerFlagShorthand = "i"
	anchorCredentialIssuerFlagUsage     = "Anchor credential issuer (required). " +
		commonEnvVarUsageText + anchorCredentialIssuerEnvKey

	anchorCredentialURLFlagName      = "anchor-credential-url"
	anchorCredentialURLEnvKey        = "ANCHOR_CREDENTIAL_URL"
	anchorCredentialURLFlagShorthand = "g"
	anchorCredentialURLFlagUsage     = "Anchor credential url (required). " +
		commonEnvVarUsageText + anchorCredentialURLEnvKey

	anchorCredentialSignatureSuiteFlagName      = "anchor-credential-signature-suite"
	anchorCredentialSignatureSuiteEnvKey        = "ANCHOR_CREDENTIAL_SIGNATURE_SUITE"
	anchorCredentialSignatureSuiteFlagShorthand = "z"
	anchorCredentialSignatureSuiteFlagUsage     = "Anchor credential signature suite (required). " +
		commonEnvVarUsageText + anchorCredentialSignatureSuiteEnvKey

	anchorCredentialDomainFlagName      = "anchor-credential-domain"
	anchorCredentialDomainEnvKey        = "ANCHOR_CREDENTIAL_DOMAIN"
	anchorCredentialDomainFlagShorthand = "d"
	anchorCredentialDomainFlagUsage     = "Anchor credential domain (required). " +
		commonEnvVarUsageText + anchorCredentialDomainEnvKey

	allowedOriginsFlagName      = "allowed-origins"
	allowedOriginsEnvKey        = "ALLOWED_ORIGINS"
	allowedOriginsFlagShorthand = "o"
	allowedOriginsFlagUsage     = "Allowed origins for this did method. " + commonEnvVarUsageText + allowedOriginsEnvKey

	maxWitnessDelayFlagName      = "max-witness-delay"
	maxWitnessDelayEnvKey        = "MAX_WITNESS_DELAY"
	maxWitnessDelayFlagShorthand = "w"
	maxWitnessDelayFlagUsage     = "Maximum witness response time (in seconds). " + commonEnvVarUsageText + maxWitnessDelayEnvKey

	signWithLocalWitnessFlagName      = "sign-with-local-witness"
	signWithLocalWitnessEnvKey        = "SIGN_WITH_LOCAL_WITNESS"
	signWithLocalWitnessFlagShorthand = "f"
	signWithLocalWitnessFlagUsage     = "Always sign with local witness flag (default true). " + commonEnvVarUsageText + signWithLocalWitnessEnvKey

	discoveryDomainsFlagName  = "discovery-domains"
	discoveryDomainsEnvKey    = "DISCOVERY_DOMAINS"
	discoveryDomainsFlagUsage = "Discovery domains. " + commonEnvVarUsageText + discoveryDomainsEnvKey

	discoveryVctDomainsFlagName  = "discovery-vct-domains"
	discoveryVctDomainsEnvKey    = "DISCOVERY_VCT_DOMAINS"
	discoveryVctDomainsFlagUsage = "Discovery vctdomains. " + commonEnvVarUsageText + discoveryVctDomainsEnvKey

	discoveryMinimumResolversFlagName  = "discovery-minimum-resolvers"
	discoveryMinimumResolversEnvKey    = "DISCOVERY_MINIMUM_RESOLVERS"
	discoveryMinimumResolversFlagUsage = "Discovery minimum resolvers number." +
		commonEnvVarUsageText + discoveryMinimumResolversEnvKey

	httpSignaturesEnabledFlagName  = "enable-http-signatures"
	httpSignaturesEnabledEnvKey    = "HTTP_SIGNATURES_ENABLED"
	httpSignaturesEnabledShorthand = "p"
	httpSignaturesEnabledUsage     = `Set to "true" to enable HTTP signatures in ActivityPub. ` +
		commonEnvVarUsageText + httpSignaturesEnabledEnvKey

	enableDidDiscoveryFlagName = "enable-did-discovery"
	enableDidDiscoveryEnvKey   = "DID_DISCOVERY_ENABLED"
	enableDidDiscoveryUsage    = `Set to "true" to enable did discovery. ` +
		commonEnvVarUsageText + enableDidDiscoveryEnvKey

	enableCreateDocumentStoreFlagName = "enable-create-document-store"
	enableCreateDocumentStoreEnvKey   = "CREATE_DOCUMENT_STORE_ENABLED"
	enableCreateDocumentStoreUsage    = `Set to "true" to enable create document store. ` +
		`Used for resolving unpublished created documents.` +
		commonEnvVarUsageText + enableCreateDocumentStoreEnvKey

	enableUpdateDocumentStoreFlagName = "enable-update-document-store"
	enableUpdateDocumentStoreEnvKey   = "UPDATE_DOCUMENT_STORE_ENABLED"
	enableUpdateDocumentStoreUsage    = `Set to "true" to enable update document store. ` +
		`Used for resolving unpublished updates for documents.` +
		commonEnvVarUsageText + enableUpdateDocumentStoreEnvKey

	includeUnpublishedOperationsFlagName = "include-unpublished-operations-in-metadata"
	includeUnpublishedOperationsEnvKey   = "INCLUDE_UNPUBLISHED_OPERATIONS_IN_METADATA"
	includeUnpublishedOperationsUsage    = `Set to "true" to include unpublished operations in metadata. ` +
		commonEnvVarUsageText + includeUnpublishedOperationsEnvKey

	includePublishedOperationsFlagName = "include-published-operations-in-metadata"
	includePublishedOperationsEnvKey   = "INCLUDE_PUBLISHED_OPERATIONS_IN_METADATA"
	includePublishedOperationsUsage    = `Set to "true" to include published operations in metadata. ` +
		commonEnvVarUsageText + includePublishedOperationsEnvKey

	resolveFromAnchorOriginFlagName = "resolve-from-anchor-origin"
	resolveFromAnchorOriginEnvKey   = "RESOLVE_FROM_ANCHOR_ORIGIN"
	resolveFromAnchorOriginUsage    = `Set to "true" to resolve from anchor origin. ` +
		commonEnvVarUsageText + resolveFromAnchorOriginEnvKey

	verifyLatestFromAnchorOriginFlagName = "verify-latest-from-anchor-origin"
	verifyLatestFromAnchorOriginEnvKey   = "VERIFY_LATEST_FROM_ANCHOR_ORIGIN"
	verifyLatestFromAnchorOriginUsage    = `Set to "true" to verify latest operations against anchor origin. ` +
		commonEnvVarUsageText + verifyLatestFromAnchorOriginEnvKey

	authTokensDefFlagName      = "auth-tokens-def"
	authTokensDefFlagShorthand = "D"
	authTokensDefFlagUsage     = "Authorization token definitions."
	authTokensDefEnvKey        = "ORB_AUTH_TOKENS_DEF"

	authTokensFlagName      = "auth-tokens"
	authTokensFlagShorthand = "A"
	authTokensFlagUsage     = "Authorization tokens."
	authTokensEnvKey        = "ORB_AUTH_TOKENS"

	activityPubPageSizeFlagName      = "activitypub-page-size"
	activityPubPageSizeFlagShorthand = "P"
	activityPubPageSizeEnvKey        = "ACTIVITYPUB_PAGE_SIZE"
	activityPubPageSizeFlagUsage     = "The maximum page size for an ActivityPub collection or ordered collection. " +
		commonEnvVarUsageText + activityPubPageSizeEnvKey

	devModeEnabledFlagName = "enable-dev-mode"
	devModeEnabledEnvKey   = "DEV_MODE_ENABLED"
	devModeEnabledUsage    = `Set to "true" to enable dev mode. ` +
		commonEnvVarUsageText + devModeEnabledEnvKey

	nodeInfoRefreshIntervalFlagName      = "nodeinfo-refresh-interval"
	nodeInfoRefreshIntervalFlagShorthand = "R"
	nodeInfoRefreshIntervalEnvKey        = "NODEINFO_REFRESH_INTERVAL"
	nodeInfoRefreshIntervalFlagUsage     = "The interval for refreshing NodeInfo data. For example, '30s' for a 30 second interval. " +
		commonEnvVarUsageText + nodeInfoRefreshIntervalEnvKey

	ipfsTimeoutFlagName      = "ipfs-timeout"
	ipfsTimeoutFlagShorthand = "T"
	ipfsTimeoutEnvKey        = "IPFS_TIMEOUT"
	ipfsTimeoutFlagUsage     = "The timeout for IPFS requests. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + ipfsTimeoutEnvKey

	contextProviderFlagName  = "context-provider-url"
	contextProviderFlagUsage = "Comma-separated list of remote context provider URLs to get JSON-LD contexts from." +
		commonEnvVarUsageText + contextProviderEnvKey
	contextProviderEnvKey = "ORB_CONTEXT_PROVIDER_URL"

	unpublishedOperationLifespanFlagName  = "unpublished-operation-lifetime"
	unpublishedOperationLifespanEnvKey    = "UNPUBLISHED_OPERATION_LIFETIME"
	unpublishedOperationLifespanFlagUsage = "How long unpublished operations remain stored before expiring " +
		"(and thus, being deleted some time later). For example, '1m' for a 1 minute lifespan. " +
		"Defaults to 1 minute if not set. " + commonEnvVarUsageText + unpublishedOperationLifespanEnvKey

	taskMgrCheckIntervalFlagName  = "task-manager-check-interval"
	taskMgrCheckIntervalEnvKey    = "TASK_MANAGER_CHECK_INTERVAL"
	taskMgrCheckIntervalFlagUsage = "How frequently to check for scheduled tasks. " +
		"For example, a setting of '10s' will cause the task manager to check for outstanding tasks every 10s. " +
		"Defaults to 10 seconds if not set. " + commonEnvVarUsageText + taskMgrCheckIntervalEnvKey

	dataExpiryCheckIntervalFlagName  = "data-expiry-check-interval"
	dataExpiryCheckIntervalEnvKey    = "DATA_EXPIRY_CHECK_INTERVAL"
	dataExpiryCheckIntervalFlagUsage = "How frequently to check for (and delete) any expired data. " +
		"For example, a setting of '1m' will cause the expiry service to run a check every 1 minute. " +
		"Defaults to 1 minute if not set. " + commonEnvVarUsageText + dataExpiryCheckIntervalEnvKey

	followAuthPolicyFlagName      = "follow-auth-policy"
	followAuthPolicyFlagShorthand = "F"
	followAuthPolicyEnvKey        = "FOLLOW_AUTH_POLICY"
	followAuthPolicyFlagUsage     = "The type of authorization to use when a 'Follow' ActivityPub request is received. " +
		"Possible values are: 'accept-all' and 'accept-list'. The value, 'accept-all', indicates that this " +
		"server will accept any 'Follow' request. The value, 'accept-list', indicates that the service sending the " +
		"'Follow' request must be included in an 'accept list'. " +
		"Defaults to 'accept-all' if not set. " + commonEnvVarUsageText + followAuthPolicyEnvKey

	inviteWitnessAuthPolicyFlagName      = "invite-witness-auth-policy"
	inviteWitnessAuthPolicyFlagShorthand = "W"
	inviteWitnessAuthPolicyEnvKey        = "INVITE_WITNESS_AUTH_POLICY"
	inviteWitnessAuthPolicyFlagUsage     = "The type of authorization to use when a 'Invite' witness ActivityPub request is received. " +
		"Possible values are: 'accept-all' and 'accept-list'. The value, 'accept-all', indicates that this " +
		"server will accept any 'Invite' request for a witness. The value, 'accept-list', indicates that the service sending the " +
		"'Invite' witness request must be included in an 'accept list'. " +
		"Defaults to 'accept-all' if not set. " + commonEnvVarUsageText + inviteWitnessAuthPolicyEnvKey

	// TODO: Update verification method
)

type acceptRejectPolicy string

const (
	acceptAllPolicy  acceptRejectPolicy = "accept-all"
	acceptListPolicy acceptRejectPolicy = "accept-list"
)

type tlsParameters struct {
	systemCertPool bool
	caCerts        []string
	serveCertPath  string
	serveKeyPath   string
}

type orbParameters struct {
	hostURL                        string
	hostMetricsURL                 string
	vctURL                         string
	keyID                          string
	privateKeyBase64               string
	secretLockKeyPath              string
	kmsEndpoint                    string
	kmsStoreEndpoint               string
	externalEndpoint               string
	discoveryDomain                string
	didNamespace                   string
	didAliases                     []string
	batchWriterTimeout             time.Duration
	casType                        string
	ipfsURL                        string
	localCASReplicateInIPFSEnabled bool
	cidVersion                     int
	mqURL                          string
	mqMaxConnectionSubscriptions   int
	dbParameters                   *dbParameters
	logLevel                       string
	methodContext                  []string
	baseEnabled                    bool
	allowedOrigins                 []string
	tlsParams                      *tlsParameters
	anchorCredentialParams         *anchorCredentialParams
	discoveryDomains               []string
	discoveryVctDomains            []string
	discoveryMinimumResolvers      int
	maxWitnessDelay                time.Duration
	syncTimeout                    uint64
	signWithLocalWitness           bool
	httpSignaturesEnabled          bool
	didDiscoveryEnabled            bool
	createDocumentStoreEnabled     bool
	updateDocumentStoreEnabled     bool
	includeUnpublishedOperations   bool
	includePublishedOperations     bool
	resolveFromAnchorOrigin        bool
	verifyLatestFromAnchorOrigin   bool
	updateDocumentStoreTypes       []operation.Type
	authTokenDefinitions           []*auth.TokenDef
	authTokens                     map[string]string
	opQueuePoolSize                uint
	observerQueuePoolSize          uint
	activityPubPageSize            int
	enableDevMode                  bool
	nodeInfoRefreshInterval        time.Duration
	ipfsTimeout                    time.Duration
	databaseTimeout                time.Duration
	contextProviderURLs            []string
	unpublishedOperationLifespan   time.Duration
	dataExpiryCheckInterval        time.Duration
	inviteWitnessAuthPolicy        acceptRejectPolicy
	followAuthPolicy               acceptRejectPolicy
	taskMgrCheckInterval           time.Duration
}

type anchorCredentialParams struct {
	verificationMethod string
	signatureSuite     string
	domain             string
	issuer             string
	url                string
}

type dbParameters struct {
	databaseType             string
	databaseURL              string
	databasePrefix           string
	kmsSecretsDatabaseType   string
	kmsSecretsDatabaseURL    string
	kmsSecretsDatabasePrefix string
}

// nolint: gocyclo,funlen
func getOrbParameters(cmd *cobra.Command) (*orbParameters, error) {
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	hostMetricsURL, err := cmdutils.GetUserSetVarFromString(cmd, hostMetricsURLFlagName, hostMetricsURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	// no need to check errors for optional flags
	vctURL, _ := cmdutils.GetUserSetVarFromString(cmd, vctURLFlagName, vctURLEnvKey, true)
	kmsStoreEndpoint, _ := cmdutils.GetUserSetVarFromString(cmd, kmsStoreEndpointFlagName, kmsStoreEndpointEnvKey, true) // nolint: errcheck,lll
	kmsEndpoint, _ := cmdutils.GetUserSetVarFromString(cmd, kmsEndpointFlagName, kmsEndpointEnvKey, true)                // nolint: errcheck,lll
	keyID := cmdutils.GetUserSetOptionalVarFromString(cmd, keyIDFlagName, keyIDEnvKey)
	privateKeyBase64 := cmdutils.GetUserSetOptionalVarFromString(cmd, privateKeyFlagName, privateKeyEnvKey)
	secretLockKeyPath, _ := cmdutils.GetUserSetVarFromString(cmd, secretLockKeyPathFlagName, secretLockKeyPathEnvKey, true) // nolint: errcheck,lll

	externalEndpoint, err := cmdutils.GetUserSetVarFromString(cmd, externalEndpointFlagName, externalEndpointEnvKey, true)
	if err != nil {
		return nil, err
	}

	if externalEndpoint == "" {
		externalEndpoint = hostURL
	}

	discoveryDomain, err := cmdutils.GetUserSetVarFromString(cmd, discoveryDomainFlagName, discoveryDomainEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	casType, err := cmdutils.GetUserSetVarFromString(cmd, casTypeFlagName, casTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	ipfsURL, err := cmdutils.GetUserSetVarFromString(cmd, ipfsURLFlagName, ipfsURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	ipfsURLParsed, err := url.Parse(ipfsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPFS URL: %w", err)
	}

	if ipfsURLParsed.Hostname() == "ipfs.io" && casType == "ipfs" {
		return nil, errors.New("CAS type cannot be set to IPFS if ipfs.io is being used as the node since it " +
			"doesn't support writes. Either switch the node URL to one that does support writes or " +
			"change the CAS type to local")
	}

	localCASReplicateInIPFSEnabledString, err := cmdutils.GetUserSetVarFromString(cmd, localCASReplicateInIPFSFlagName,
		localCASReplicateInIPFSEnvKey, true)
	if err != nil {
		return nil, err
	}

	localCASReplicateInIPFSEnabled := defaultLocalCASReplicateInIPFSEnabled
	if localCASReplicateInIPFSEnabledString != "" && ipfsURLParsed.Hostname() != "ipfs.io" {
		enable, parseErr := strconv.ParseBool(localCASReplicateInIPFSEnabledString)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", localCASReplicateInIPFSFlagName, parseErr)
		}

		localCASReplicateInIPFSEnabled = enable
	}

	mqURL, mqOpPoolSize, mqObserverPoolSize, mqMaxSubscriptionsPerConnection, err := getMQParameters(cmd)
	if err != nil {
		return nil, err
	}

	cidVersionString, err := cmdutils.GetUserSetVarFromString(cmd, cidVersionFlagName, cidVersionEnvKey, true)
	if err != nil {
		return nil, err
	}

	var cidVersion int

	if cidVersionString == "" {
		// default to v1 if no version specified
		cidVersion = 1
	} else if cidVersionString != "0" && cidVersionString != "1" {
		return nil, fmt.Errorf("invalid CID version specified. Must be either 0 or 1")
	} else {
		cidVersion, err = strconv.Atoi(cidVersionString)
		if err != nil {
			return nil, fmt.Errorf("failed to convert CID version string to an integer: %w", err)
		}
	}

	batchWriterTimeoutStr, err := cmdutils.GetUserSetVarFromString(cmd, batchWriterTimeoutFlagName, batchWriterTimeoutEnvKey, true)
	if err != nil {
		return nil, err
	}

	batchWriterTimeout := defaultBatchWriterTimeout
	if batchWriterTimeoutStr != "" {
		timeout, parseErr := strconv.ParseUint(batchWriterTimeoutStr, 10, 32)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid batch writer timeout format: %s", parseErr.Error())
		}

		batchWriterTimeout = time.Duration(timeout) * time.Millisecond
	}

	maxWitnessDelayStr, err := cmdutils.GetUserSetVarFromString(cmd, maxWitnessDelayFlagName, maxWitnessDelayEnvKey, true)
	if err != nil {
		return nil, err
	}

	maxWitnessDelay := defaultMaxWitnessDelay
	if maxWitnessDelayStr != "" {
		delay, parseErr := strconv.ParseUint(maxWitnessDelayStr, 10, 32)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid max witness delay format: %s", parseErr.Error())
		}

		maxWitnessDelay = time.Duration(delay) * time.Second
	}

	signWithLocalWitnessStr, err := cmdutils.GetUserSetVarFromString(cmd, signWithLocalWitnessFlagName, signWithLocalWitnessEnvKey, true)
	if err != nil {
		return nil, err
	}

	// default behaviour is to always sign with local witness
	signWithLocalWitness := true
	if signWithLocalWitnessStr != "" {
		signWithLocalWitness, err = strconv.ParseBool(signWithLocalWitnessStr)
		if err != nil {
			return nil, fmt.Errorf("invalid sign with local witness flag value: %s", err.Error())
		}
	}

	syncTimeoutStr := cmdutils.GetUserSetOptionalVarFromString(cmd, syncTimeoutFlagName, syncTimeoutEnvKey)

	syncTimeout := uint64(defaultSyncTimeout)

	if syncTimeoutStr != "" {
		syncTimeout, err = strconv.ParseUint(syncTimeoutStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("sync timeout is not a number(positive): %w", err)
		}
	}

	httpSignaturesEnabledStr, err := cmdutils.GetUserSetVarFromString(cmd, httpSignaturesEnabledFlagName, httpSignaturesEnabledEnvKey, true)
	if err != nil {
		return nil, err
	}

	httpSignaturesEnabled := defaulthttpSignaturesEnabled
	if httpSignaturesEnabledStr != "" {
		enable, parseErr := strconv.ParseBool(httpSignaturesEnabledStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", httpSignaturesEnabledFlagName, parseErr)
		}

		httpSignaturesEnabled = enable
	}

	enableDidDiscoveryStr, err := cmdutils.GetUserSetVarFromString(cmd, enableDidDiscoveryFlagName, enableDidDiscoveryEnvKey, true)
	if err != nil {
		return nil, err
	}

	didDiscoveryEnabled := defaultDidDiscoveryEnabled
	if enableDidDiscoveryStr != "" {
		enable, parseErr := strconv.ParseBool(enableDidDiscoveryStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", enableDidDiscoveryFlagName, parseErr)
		}

		didDiscoveryEnabled = enable
	}

	enableDevModeStr := cmdutils.GetUserSetOptionalVarFromString(cmd, devModeEnabledFlagName, devModeEnabledEnvKey)

	enableDevMode := defaultDevModeEnabled
	if enableDevModeStr != "" {
		enable, parseErr := strconv.ParseBool(enableDevModeStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", devModeEnabledFlagName, parseErr)
		}

		enableDevMode = enable
	}

	enableCreateDocStoreStr, err := cmdutils.GetUserSetVarFromString(cmd, enableCreateDocumentStoreFlagName, enableCreateDocumentStoreEnvKey, true)
	if err != nil {
		return nil, err
	}

	createDocumentStoreEnabled := defaultCreateDocumentStoreEnabled
	if enableCreateDocStoreStr != "" {
		enable, parseErr := strconv.ParseBool(enableCreateDocStoreStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", enableCreateDocumentStoreFlagName, parseErr)
		}

		createDocumentStoreEnabled = enable
	}

	enableUpdateDocStoreStr, err := cmdutils.GetUserSetVarFromString(cmd, enableUpdateDocumentStoreFlagName, enableUpdateDocumentStoreEnvKey, true)
	if err != nil {
		return nil, err
	}

	updateDocumentStoreEnabled := defaultUpdateDocumentStoreEnabled
	if enableUpdateDocStoreStr != "" {
		enable, parseErr := strconv.ParseBool(enableUpdateDocStoreStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", enableUpdateDocumentStoreFlagName, parseErr)
		}

		updateDocumentStoreEnabled = enable
	}

	includeUnpublishedOperationsStr, err := cmdutils.GetUserSetVarFromString(cmd, includeUnpublishedOperationsFlagName, includeUnpublishedOperationsEnvKey, true)
	if err != nil {
		return nil, err
	}

	includeUnpublishedOperations := defaultIncludeUnpublishedOperations
	if includeUnpublishedOperationsStr != "" {
		enable, parseErr := strconv.ParseBool(includeUnpublishedOperationsStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", includeUnpublishedOperationsFlagName, parseErr)
		}

		includeUnpublishedOperations = enable
	}

	includePublishedOperationsStr, err := cmdutils.GetUserSetVarFromString(cmd, includePublishedOperationsFlagName, includePublishedOperationsEnvKey, true)
	if err != nil {
		return nil, err
	}

	includePublishedOperations := defaultIncludePublishedOperations
	if includePublishedOperationsStr != "" {
		enable, parseErr := strconv.ParseBool(includePublishedOperationsStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", includePublishedOperationsFlagName, parseErr)
		}

		includePublishedOperations = enable
	}

	resolveFromAnchorOriginStr, err := cmdutils.GetUserSetVarFromString(cmd, resolveFromAnchorOriginFlagName, resolveFromAnchorOriginEnvKey, true)
	if err != nil {
		return nil, err
	}

	resolveFromAnchorOrigin := defaultResolveFromAnchorOrigin
	if resolveFromAnchorOriginStr != "" {
		enable, parseErr := strconv.ParseBool(resolveFromAnchorOriginStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", resolveFromAnchorOriginFlagName, parseErr)
		}

		resolveFromAnchorOrigin = enable
	}

	verifyLatestFromAnchorOriginStr, err := cmdutils.GetUserSetVarFromString(cmd, verifyLatestFromAnchorOriginFlagName, verifyLatestFromAnchorOriginEnvKey, true)
	if err != nil {
		return nil, err
	}

	verifyLatestFromAnchorOrigin := defaultVerifyLatestFromAnchorOrigin
	if verifyLatestFromAnchorOriginStr != "" {
		enable, parseErr := strconv.ParseBool(verifyLatestFromAnchorOriginStr)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid value for %s: %s", verifyLatestFromAnchorOriginFlagName, parseErr)
		}

		verifyLatestFromAnchorOrigin = enable
	}

	didNamespace, err := cmdutils.GetUserSetVarFromString(cmd, didNamespaceFlagName, didNamespaceEnvKey, false)
	if err != nil {
		return nil, err
	}

	didAliases := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, didAliasesFlagName, didAliasesEnvKey)

	dbParams, err := getDBParameters(cmd, kmsStoreEndpoint != "" || kmsEndpoint != "")
	if err != nil {
		return nil, err
	}

	loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, LogLevelFlagName, LogLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	anchorCredentialParams, err := getAnchorCredentialParameters(cmd, externalEndpoint)
	if err != nil {
		return nil, err
	}

	allowedOrigins, err := cmdutils.GetUserSetVarFromArrayString(cmd, allowedOriginsFlagName, allowedOriginsEnvKey, true)
	if err != nil {
		return nil, err
	}

	discoveryDomains := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, discoveryDomainsFlagName, discoveryDomainsEnvKey)

	discoveryVctDomains := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, discoveryVctDomainsFlagName, discoveryVctDomainsEnvKey)

	discoveryMinimumResolversStr := cmdutils.GetUserSetOptionalVarFromString(cmd, discoveryMinimumResolversFlagName,
		discoveryMinimumResolversEnvKey)

	discoveryMinimumResolvers := defaultDiscoveryMinimumResolvers
	if discoveryMinimumResolversStr != "" {
		discoveryMinimumResolvers, err = strconv.Atoi(discoveryMinimumResolversStr)
		if err != nil {
			return nil, fmt.Errorf("invalid discovery minimum resolvers: %s", err.Error())
		}
	}

	authTokenDefs, err := getAuthTokenDefinitions(cmd)
	if err != nil {
		return nil, fmt.Errorf("authorization token definitions: %w", err)
	}

	authTokens, err := getAuthTokens(cmd)
	if err != nil {
		return nil, fmt.Errorf("authorization tokens: %w", err)
	}

	activityPubPageSize, err := getActivityPubPageSize(cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", activityPubPageSizeFlagName, err)
	}

	nodeInfoRefreshInterval, err := getDuration(cmd, nodeInfoRefreshIntervalFlagName,
		nodeInfoRefreshIntervalEnvKey, defaultNodeInfoRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", nodeInfoRefreshIntervalFlagName, err)
	}

	ipfsTimeout, err := getDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ipfsTimeoutFlagName, err)
	}

	databaseTimeout, err := getDuration(cmd, databaseURLFlagName, databaseTimeoutEnvKey, defaultDatabaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", databaseTimeoutFlagName, err)
	}

	contextProviderURLs, err := cmdutils.GetUserSetVarFromArrayString(cmd, contextProviderFlagName, contextProviderEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", contextProviderFlagName, err)
	}

	unpublishedOperationLifespan, err := getDuration(cmd, unpublishedOperationLifespanFlagName,
		unpublishedOperationLifespanEnvKey, defaultUnpublishedOperationLifespan)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", unpublishedOperationLifespanFlagName, err)
	}

	dataExpiryCheckInterval, err := getDuration(cmd, dataExpiryCheckIntervalFlagName,
		dataExpiryCheckIntervalEnvKey, defaultDataExpiryCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dataExpiryCheckIntervalFlagName, err)
	}

	taskMgrCheckInterval, err := getDuration(cmd, taskMgrCheckIntervalFlagName,
		taskMgrCheckIntervalEnvKey, defaultTaskMgrCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", taskMgrCheckIntervalFlagName, err)
	}

	followAuthPolicy, err := getFollowAuthPolicy(cmd)
	if err != nil {
		return nil, err
	}

	inviteWitnessAuthPolicy, err := getInviteWitnessAuthPolicy(cmd)
	if err != nil {
		return nil, err
	}

	return &orbParameters{
		hostURL:                        hostURL,
		hostMetricsURL:                 hostMetricsURL,
		vctURL:                         vctURL,
		kmsEndpoint:                    kmsEndpoint,
		keyID:                          keyID,
		privateKeyBase64:               privateKeyBase64,
		secretLockKeyPath:              secretLockKeyPath,
		kmsStoreEndpoint:               kmsStoreEndpoint,
		discoveryDomain:                discoveryDomain,
		externalEndpoint:               externalEndpoint,
		tlsParams:                      tlsParams,
		didNamespace:                   didNamespace,
		didAliases:                     didAliases,
		allowedOrigins:                 allowedOrigins,
		casType:                        casType,
		ipfsURL:                        ipfsURL,
		localCASReplicateInIPFSEnabled: localCASReplicateInIPFSEnabled,
		cidVersion:                     cidVersion,
		mqURL:                          mqURL,
		mqMaxConnectionSubscriptions:   mqMaxSubscriptionsPerConnection,
		opQueuePoolSize:                uint(mqOpPoolSize),
		observerQueuePoolSize:          uint(mqObserverPoolSize),
		batchWriterTimeout:             batchWriterTimeout,
		anchorCredentialParams:         anchorCredentialParams,
		logLevel:                       loggingLevel,
		dbParameters:                   dbParams,
		discoveryDomains:               discoveryDomains,
		discoveryVctDomains:            discoveryVctDomains,
		discoveryMinimumResolvers:      discoveryMinimumResolvers,
		maxWitnessDelay:                maxWitnessDelay,
		syncTimeout:                    syncTimeout,
		signWithLocalWitness:           signWithLocalWitness,
		httpSignaturesEnabled:          httpSignaturesEnabled,
		didDiscoveryEnabled:            didDiscoveryEnabled,
		createDocumentStoreEnabled:     createDocumentStoreEnabled,
		updateDocumentStoreEnabled:     updateDocumentStoreEnabled,
		includePublishedOperations:     includePublishedOperations,
		includeUnpublishedOperations:   includeUnpublishedOperations,
		resolveFromAnchorOrigin:        resolveFromAnchorOrigin,
		verifyLatestFromAnchorOrigin:   verifyLatestFromAnchorOrigin,
		authTokenDefinitions:           authTokenDefs,
		authTokens:                     authTokens,
		activityPubPageSize:            activityPubPageSize,
		enableDevMode:                  enableDevMode,
		nodeInfoRefreshInterval:        nodeInfoRefreshInterval,
		ipfsTimeout:                    ipfsTimeout,
		databaseTimeout:                databaseTimeout,
		contextProviderURLs:            contextProviderURLs,
		unpublishedOperationLifespan:   unpublishedOperationLifespan,
		dataExpiryCheckInterval:        dataExpiryCheckInterval,
		followAuthPolicy:               followAuthPolicy,
		inviteWitnessAuthPolicy:        inviteWitnessAuthPolicy,
		taskMgrCheckInterval:           taskMgrCheckInterval,
	}, nil
}

func getAnchorCredentialParameters(cmd *cobra.Command, externalEndpoint string) (*anchorCredentialParams, error) {
	domain := cmdutils.GetUserSetOptionalVarFromString(cmd, anchorCredentialDomainFlagName, anchorCredentialDomainEnvKey)
	if domain == "" {
		domain = externalEndpoint
	}

	issuer := cmdutils.GetUserSetOptionalVarFromString(cmd, anchorCredentialIssuerFlagName, anchorCredentialIssuerEnvKey)
	if issuer == "" {
		issuer = externalEndpoint
	}

	url := cmdutils.GetUserSetOptionalVarFromString(cmd, anchorCredentialURLFlagName, anchorCredentialURLEnvKey)
	if url == "" {
		url = fmt.Sprintf("%s/vc", externalEndpoint)
	}

	signatureSuite, err := cmdutils.GetUserSetVarFromString(cmd, anchorCredentialSignatureSuiteFlagName, anchorCredentialSignatureSuiteEnvKey, false)
	if err != nil {
		return nil, err
	}

	// TODO: Add verification method here

	return &anchorCredentialParams{
		issuer:         issuer,
		url:            url,
		domain:         domain,
		signatureSuite: signatureSuite,
	}, nil
}

func getDBParameters(cmd *cobra.Command, kmOptional bool) (*dbParameters, error) {
	databaseType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName,
		databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	databaseURL, err := cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName,
		databaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName,
		databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyDatabaseType, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabaseTypeFlagName,
		kmsSecretsDatabaseTypeEnvKey, kmOptional)
	if err != nil {
		return nil, err
	}

	keyDatabaseURL, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabaseURLFlagName,
		kmsSecretsDatabaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyDatabasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, kmsSecretsDatabasePrefixFlagName,
		kmsSecretsDatabasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	return &dbParameters{
		databaseType:             databaseType,
		databaseURL:              databaseURL,
		databasePrefix:           databasePrefix,
		kmsSecretsDatabaseType:   keyDatabaseType,
		kmsSecretsDatabaseURL:    keyDatabaseURL,
		kmsSecretsDatabasePrefix: keyDatabasePrefix,
	}, nil
}

func getAuthTokenDefinitions(cmd *cobra.Command) ([]*auth.TokenDef, error) {
	authTokenDefsStr, err := cmdutils.GetUserSetVarFromArrayString(cmd, authTokensDefFlagName, authTokensDefEnvKey, true)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Auth tokens definition: %s", authTokenDefsStr)

	var authTokenDefs []*auth.TokenDef

	for _, defStr := range authTokenDefsStr {
		parts := strings.Split(defStr, "|")
		if len(parts) < 1 || len(parts) > 3 {
			return nil, fmt.Errorf("invalid auth token definition %s: %w", defStr, err)
		}

		var readTokens []string
		var writeTokens []string

		if len(parts) > 1 {
			readTokens = filterEmptyTokens(strings.Split(parts[1], "&"))
		}

		if len(parts) > 2 {
			writeTokens = filterEmptyTokens(strings.Split(parts[2], "&"))
		}

		def := &auth.TokenDef{
			EndpointExpression: parts[0],
			ReadTokens:         readTokens,
			WriteTokens:        writeTokens,
		}

		logger.Debugf("Adding auth token definition for endpoint %s - Read Tokens: %s, Write Tokens: %s",
			def.EndpointExpression, def.ReadTokens, def.WriteTokens)

		authTokenDefs = append(authTokenDefs, def)
	}

	return authTokenDefs, nil
}

func filterEmptyTokens(tokens []string) []string {
	var nonEmptyTokens []string

	for _, token := range tokens {
		if token != "" {
			nonEmptyTokens = append(nonEmptyTokens, token)
		}
	}

	return nonEmptyTokens
}

func getAuthTokens(cmd *cobra.Command) (map[string]string, error) {
	authTokensStr, err := cmdutils.GetUserSetVarFromArrayString(cmd, authTokensFlagName, authTokensEnvKey, true)
	if err != nil {
		return nil, err
	}

	authTokens := make(map[string]string)

	for _, keyValStr := range authTokensStr {
		keyVal := strings.Split(keyValStr, "=")

		if len(keyVal) != 2 {
			return nil, fmt.Errorf("invalid auth token string [%s]: %w", authTokensStr, err)
		}

		logger.Debugf("Adding token %s=%s", keyVal[0], keyVal[1])

		authTokens[keyVal[0]] = keyVal[1]
	}

	return authTokens, nil
}

func getActivityPubPageSize(cmd *cobra.Command) (int, error) {
	activityPubPageSizeStr, err := cmdutils.GetUserSetVarFromString(cmd, activityPubPageSizeFlagName, activityPubPageSizeEnvKey, true)
	if err != nil {
		return 0, err
	}

	if activityPubPageSizeStr == "" {
		return defaultActivityPubPageSize, nil
	}

	activityPubPageSize, err := strconv.Atoi(activityPubPageSizeStr)
	if err != nil {
		return 0, fmt.Errorf("invalid value [%s]: %w", activityPubPageSizeStr, err)
	}

	if activityPubPageSize <= 0 {
		return 0, errors.New("value must be greater than 0")
	}

	return activityPubPageSize, nil
}

func getDuration(cmd *cobra.Command, flagName, envKey string,
	defaultDuration time.Duration) (time.Duration, error) {
	timeoutStr, err := cmdutils.GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return -1, err
	}

	if timeoutStr == "" {
		return defaultDuration, nil
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return -1, fmt.Errorf("invalid value [%s]: %w", timeoutStr, err)
	}

	return timeout, nil
}

func getMQParameters(cmd *cobra.Command) (mqURL string, mqOpPoolSize int, mqObserverPoolSize int,
	mqMaxConnectionSubscriptions int, err error) {
	mqURL, err = cmdutils.GetUserSetVarFromString(cmd, mqURLFlagName, mqURLEnvKey, true)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("%s: %w", mqURLFlagName, err)
	}

	mqOpPoolStr, err := cmdutils.GetUserSetVarFromString(cmd, mqOpPoolFlagName, mqOpPoolEnvKey, true)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("%s: %w", mqOpPoolFlagName, err)
	}

	if mqOpPoolStr != "" {
		mqOpPoolSize, err = strconv.Atoi(mqOpPoolStr)
		if err != nil {
			return "", 0, 0, 0, fmt.Errorf("invalid value for %s [%s]: %w", mqOpPoolFlagName, mqOpPoolStr, err)
		}
	}

	mqObserverPoolStr, err := cmdutils.GetUserSetVarFromString(cmd, mqObserverPoolFlagName, mqObserverPoolEnvKey, true)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("%s: %w", mqObserverPoolFlagName, err)
	}

	if mqObserverPoolStr != "" {
		mqObserverPoolSize, err = strconv.Atoi(mqObserverPoolStr)
		if err != nil {
			return "", 0, 0, 0, fmt.Errorf("invalid value for %s [%s]: %w", mqObserverPoolFlagName, mqObserverPoolStr, err)
		}
	}

	mqMaxConnectionSubscriptionsStr, err := cmdutils.GetUserSetVarFromString(cmd, mqMaxConnectionSubscriptionsFlagName,
		mqMaxConnectionSubscriptionsEnvKey, true)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("%s: %w", mqMaxConnectionSubscriptionsFlagName, err)
	}

	if mqMaxConnectionSubscriptionsStr != "" {
		mqMaxConnectionSubscriptions, err = strconv.Atoi(mqMaxConnectionSubscriptionsStr)
		if err != nil {
			return "", 0, 0, 0, fmt.Errorf("invalid value for %s [%s]: %w", mqMaxConnectionSubscriptionsFlagName, mqMaxConnectionSubscriptionsStr, err)
		}
	} else {
		mqMaxConnectionSubscriptions = mqDefaultMaxConnectionSubscriptions
	}

	return mqURL, mqOpPoolSize, mqObserverPoolSize, mqMaxConnectionSubscriptions, nil
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error

		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsCertificateFlagName, tlsCertificateLEnvKey)

	tlsServeKeyPath := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsKeyFlagName, tlsKeyEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func getFollowAuthPolicy(cmd *cobra.Command) (acceptRejectPolicy, error) {
	authType, err := cmdutils.GetUserSetVarFromString(cmd, followAuthPolicyFlagName, followAuthPolicyEnvKey, true)
	if err != nil {
		return "", fmt.Errorf("%s: %w", followAuthPolicyFlagName, err)
	}

	followAuthType := acceptRejectPolicy(authType)

	if followAuthType == "" {
		followAuthType = defaultFollowAuthType
	} else if followAuthType != acceptAllPolicy && followAuthType != acceptListPolicy {
		return "", fmt.Errorf("unsupported accept/reject authorization type: %s",
			followAuthType)
	}

	return followAuthType, nil
}

func getInviteWitnessAuthPolicy(cmd *cobra.Command) (acceptRejectPolicy, error) {
	authType, err := cmdutils.GetUserSetVarFromString(cmd, inviteWitnessAuthPolicyFlagName, inviteWitnessAuthPolicyEnvKey, true)
	if err != nil {
		return "", fmt.Errorf("%s: %w", inviteWitnessAuthPolicyFlagName, err)
	}

	inviteWitnessAuthType := acceptRejectPolicy(authType)

	if inviteWitnessAuthType == "" {
		inviteWitnessAuthType = defaultInviteWitnessAuthType
	} else if inviteWitnessAuthType != acceptAllPolicy && inviteWitnessAuthType != acceptListPolicy {
		return "", fmt.Errorf("unsupported accept/reject authorization type: %s",
			inviteWitnessAuthType)
	}

	return inviteWitnessAuthType, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(hostMetricsURLFlagName, hostMetricsURLFlagShorthand, "", hostMetricsURLFlagUsage)
	startCmd.Flags().String(syncTimeoutFlagName, "1", syncTimeoutFlagUsage)
	startCmd.Flags().String(vctURLFlagName, "", vctURLFlagUsage)
	startCmd.Flags().String(kmsStoreEndpointFlagName, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().String(kmsEndpointFlagName, "", kmsEndpointFlagUsage)
	startCmd.Flags().String(keyIDFlagName, "", keyIDFlagUsage)
	startCmd.Flags().String(privateKeyFlagName, "", privateKeyFlagUsage)
	startCmd.Flags().String(secretLockKeyPathFlagName, "", secretLockKeyPathFlagUsage)
	startCmd.Flags().StringP(externalEndpointFlagName, externalEndpointFlagShorthand, "", externalEndpointFlagUsage)
	startCmd.Flags().String(discoveryDomainFlagName, "", discoveryDomainFlagUsage)
	startCmd.Flags().StringP(tlsCertificateFlagName, tlsCertificateFlagShorthand, "", tlsCertificateFlagUsage)
	startCmd.Flags().StringP(tlsKeyFlagName, tlsKeyFlagShorthand, "", tlsKeyFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(batchWriterTimeoutFlagName, batchWriterTimeoutFlagShorthand, "", batchWriterTimeoutFlagUsage)
	startCmd.Flags().StringP(maxWitnessDelayFlagName, maxWitnessDelayFlagShorthand, "", maxWitnessDelayFlagUsage)
	startCmd.Flags().StringP(signWithLocalWitnessFlagName, signWithLocalWitnessFlagShorthand, "", signWithLocalWitnessFlagUsage)
	startCmd.Flags().StringP(httpSignaturesEnabledFlagName, httpSignaturesEnabledShorthand, "", httpSignaturesEnabledUsage)
	startCmd.Flags().String(enableDidDiscoveryFlagName, "", enableDidDiscoveryUsage)
	startCmd.Flags().String(enableCreateDocumentStoreFlagName, "", enableCreateDocumentStoreUsage)
	startCmd.Flags().String(enableUpdateDocumentStoreFlagName, "", enableUpdateDocumentStoreUsage)
	startCmd.Flags().String(includeUnpublishedOperationsFlagName, "", includeUnpublishedOperationsUsage)
	startCmd.Flags().String(includePublishedOperationsFlagName, "", includePublishedOperationsUsage)
	startCmd.Flags().String(resolveFromAnchorOriginFlagName, "", resolveFromAnchorOriginUsage)
	startCmd.Flags().String(verifyLatestFromAnchorOriginFlagName, "", verifyLatestFromAnchorOriginUsage)
	startCmd.Flags().StringP(casTypeFlagName, casTypeFlagShorthand, "", casTypeFlagUsage)
	startCmd.Flags().StringP(ipfsURLFlagName, ipfsURLFlagShorthand, "", ipfsURLFlagUsage)
	startCmd.Flags().StringP(localCASReplicateInIPFSFlagName, "", "false", localCASReplicateInIPFSFlagUsage)
	startCmd.Flags().StringP(mqURLFlagName, mqURLFlagShorthand, "", mqURLFlagUsage)
	startCmd.Flags().StringP(mqOpPoolFlagName, mqOpPoolFlagShorthand, "", mqOpPoolFlagUsage)
	startCmd.Flags().StringP(mqObserverPoolFlagName, mqObserverPoolFlagShorthand, "", mqObserverPoolFlagUsage)
	startCmd.Flags().StringP(mqMaxConnectionSubscriptionsFlagName, mqMaxConnectionSubscriptionsFlagShorthand, "", mqMaxConnectionSubscriptionsFlagUsage)
	startCmd.Flags().String(cidVersionFlagName, "1", cidVersionFlagUsage)
	startCmd.Flags().StringP(didNamespaceFlagName, didNamespaceFlagShorthand, "", didNamespaceFlagUsage)
	startCmd.Flags().StringArrayP(didAliasesFlagName, didAliasesFlagShorthand, []string{}, didAliasesFlagUsage)
	startCmd.Flags().StringArrayP(allowedOriginsFlagName, allowedOriginsFlagShorthand, []string{}, allowedOriginsFlagUsage)
	startCmd.Flags().StringP(anchorCredentialDomainFlagName, anchorCredentialDomainFlagShorthand, "", anchorCredentialDomainFlagUsage)
	startCmd.Flags().StringP(anchorCredentialIssuerFlagName, anchorCredentialIssuerFlagShorthand, "", anchorCredentialIssuerFlagUsage)
	startCmd.Flags().StringP(anchorCredentialURLFlagName, anchorCredentialURLFlagShorthand, "", anchorCredentialURLFlagUsage)
	startCmd.Flags().StringP(anchorCredentialSignatureSuiteFlagName, anchorCredentialSignatureSuiteFlagShorthand, "", anchorCredentialSignatureSuiteFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, "", "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseTypeFlagName, kmsSecretsDatabaseTypeFlagShorthand, "",
		kmsSecretsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabaseURLFlagName, kmsSecretsDatabaseURLFlagShorthand, "",
		kmsSecretsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(kmsSecretsDatabasePrefixFlagName, "", "", kmsSecretsDatabasePrefixFlagUsage)
	startCmd.Flags().StringP(LogLevelFlagName, LogLevelFlagShorthand, "", LogLevelPrefixFlagUsage)
	startCmd.Flags().StringArrayP(discoveryDomainsFlagName, "", []string{}, discoveryDomainsFlagUsage)
	startCmd.Flags().StringArrayP(discoveryVctDomainsFlagName, "", []string{}, discoveryVctDomainsFlagUsage)
	startCmd.Flags().StringP(discoveryMinimumResolversFlagName, "", "", discoveryMinimumResolversFlagUsage)
	startCmd.Flags().StringArrayP(authTokensDefFlagName, authTokensDefFlagShorthand, nil, authTokensDefFlagUsage)
	startCmd.Flags().StringArrayP(authTokensFlagName, authTokensFlagShorthand, nil, authTokensFlagUsage)
	startCmd.Flags().StringP(activityPubPageSizeFlagName, activityPubPageSizeFlagShorthand, "", activityPubPageSizeFlagUsage)
	startCmd.Flags().String(devModeEnabledFlagName, "false", devModeEnabledUsage)
	startCmd.Flags().StringP(nodeInfoRefreshIntervalFlagName, nodeInfoRefreshIntervalFlagShorthand, "", nodeInfoRefreshIntervalFlagUsage)
	startCmd.Flags().StringP(ipfsTimeoutFlagName, ipfsTimeoutFlagShorthand, "", ipfsTimeoutFlagUsage)
	startCmd.Flags().StringArrayP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
	startCmd.Flags().StringP(databaseTimeoutFlagName, "", "", databaseTimeoutFlagUsage)
	startCmd.Flags().StringP(unpublishedOperationLifespanFlagName, "", "", unpublishedOperationLifespanFlagUsage)
	startCmd.Flags().StringP(taskMgrCheckIntervalFlagName, "", "", taskMgrCheckIntervalFlagUsage)
	startCmd.Flags().StringP(dataExpiryCheckIntervalFlagName, "", "", dataExpiryCheckIntervalFlagUsage)
	startCmd.Flags().StringP(followAuthPolicyFlagName, followAuthPolicyFlagShorthand, "", followAuthPolicyFlagUsage)
	startCmd.Flags().StringP(inviteWitnessAuthPolicyFlagName, inviteWitnessAuthPolicyFlagShorthand, "", inviteWitnessAuthPolicyFlagUsage)
}
