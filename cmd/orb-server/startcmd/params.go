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

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/spf13/cobra"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	logfields "github.com/trustbloc/orb/internal/pkg/log"
	aphandler "github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/context/opqueue"
	"github.com/trustbloc/orb/pkg/datauri"
	"github.com/trustbloc/orb/pkg/document/util"
	"github.com/trustbloc/orb/pkg/httpserver/auth"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

// kmsMode kms mode
type kmsMode string

// KMS params
//
//nolint:gosec
const (
	kmsLocal kmsMode = "local"
	kmsWeb   kmsMode = "web"
	kmsAWS   kmsMode = "aws"

	kmsTypeFlagName  = "kms-type"
	kmsTypeEnvKey    = "ORB_KMS_TYPE"
	kmsTypeFlagUsage = "KMS type (local,web,aws)." +
		" Alternatively, this can be set with the following environment variable: " + kmsTypeEnvKey

	kmsEndpointFlagName  = "kms-endpoint"
	kmsEndpointEnvKey    = "ORB_KMS_ENDPOINT"
	kmsEndpointFlagUsage = "KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	kmsRegionFlagName  = "kms-region"
	kmsRegionEnvKey    = "ORB_KMS_REGION"
	kmsRegionFlagUsage = "KMS region." +
		" Alternatively, this can be set with the following environment variable: " + kmsEndpointEnvKey

	vcSignActiveKeyIDFlagName  = "vc-sign-active-key-id"
	vcSignActiveKeyIDEnvKey    = "ORB_VC_SIGN_ACTIVE_KEY_ID"
	vcSignActiveKeyIDFlagUsage = "VC Sign Active Key ID (ED25519Type)." +
		" Alternatively, this can be set with the following environment variable: " + vcSignActiveKeyIDEnvKey

	vcSignPrivateKeysFlagName  = "vc-sign-private-keys"
	vcSignPrivateKeysEnvKey    = "ORB_VC_SIGN_PRIVATE_KEYS"
	vcSignPrivateKeysFlagUsage = "VC Sign Private Keys base64 (ED25519Type)." +
		" For example,  key1=privatekeyBase64Value,key2=privatekeyBase64Value" +
		" Alternatively, this can be set with the following environment variable: " + vcSignPrivateKeysEnvKey

	vcSignKeysIDFlagName  = "vc-sign-keys-id"
	vcSignKeysIDEnvKey    = "ORB_VC_SIGN_KEYS_ID"
	vcSignKeysIDFlagUsage = "VC Sign Keys id in kms. " + commonEnvVarUsageText + vcSignKeysIDEnvKey

	httpSignActiveKeyIDFlagName  = "http-sign-active-key-id"
	httpSignActiveKeyIDEnvKey    = "ORB_HTTP_SIGN_ACTIVE_KEY_ID"
	httpSignActiveKeyIDFlagUsage = "HTTP Sign Active Key ID (ED25519Type)." +
		" Alternatively, this can be set with the following environment variable: " + httpSignActiveKeyIDEnvKey

	httpSignPrivateKeyFlagName  = "http-sign-private-key"
	httpSignPrivateKeyEnvKey    = "ORB_HTTP_SIGN_PRIVATE_KEY"
	httpSignPrivateKeyFlagUsage = "HTTP Sign Private Key base64 (ED25519Type)." +
		" For example,  key1=privatekeyBase64Value" +
		" Alternatively, this can be set with the following environment variable: " + httpSignPrivateKeyEnvKey

	secretLockKeyPathFlagName  = "secret-lock-key-path"
	secretLockKeyPathEnvKey    = "ORB_SECRET_LOCK_KEY_PATH"
	secretLockKeyPathFlagUsage = "The path to the file with key to be used by local secret lock. If missing noop " +
		"service lock is used. " + commonEnvVarUsageText + secretLockKeyPathEnvKey

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
)

//nolint:gosec,lll
const (
	defaultBatchWriterTimeout               = 60000 * time.Millisecond
	defaultDiscoveryMinimumResolvers        = 1
	defaultActivityPubPageSize              = 50
	defaultNodeInfoRefreshInterval          = 15 * time.Second
	defaultIPFSTimeout                      = 20 * time.Second
	defaultDatabaseTimeout                  = 10 * time.Second
	defaultHTTPDialTimeout                  = 2 * time.Second
	defaultServerIdleTimeout                = 20 * time.Second
	defaultServerReadHeaderTimeout          = 20 * time.Second
	defaultHTTPTimeout                      = 20 * time.Second
	defaultUnpublishedOperationLifespan     = time.Minute * 5
	defaultTaskMgrCheckInterval             = 10 * time.Second
	defaultDataExpiryCheckInterval          = time.Minute
	defaultAnchorSyncInterval               = time.Minute
	defaultAnchorSyncAcceleratedInterval    = 15 * time.Second
	defaultAnchorSyncMinActivityAge         = 10 * time.Minute
	defaultAnchorSyncMaxActivities          = 500
	defaultVCTProofMonitoringInterval       = 10 * time.Second
	defaultVCTLogMonitoringInterval         = 10 * time.Second
	defaultVCTLogMonitoringMaxTreeSize      = 50000
	defaultVCTLogMonitoringGetEntriesRange  = 1000
	defaultVCTLogEntriesStoreEnabled        = false
	defaultAnchorStatusMonitoringInterval   = 5 * time.Second
	defaultAnchorStatusInProcessGracePeriod = 30 * time.Second
	mqDefaultMaxConnectionSubscriptions     = 1000
	mqDefaultPublisherChannelPoolSize       = 25
	mqDefaultPublisherConfirmDelivery       = true
	mqDefaultObserverPoolSize               = 5
	mqDefaultOutboxPoolSize                 = 5
	mqDefaultInboxPoolSize                  = 5
	mqDefaultOpQueuePoolSize                = 5
	mqDefaultAnchorLinksetPoolSize          = 5
	mqDefaultConnectMaxRetries              = 25
	mqDefaultRedeliveryMaxAttempts          = 30
	mqDefaultRedeliveryMultiplier           = 1.5
	mqDefaultRedeliveryInitialInterval      = 2 * time.Second
	mqDefaultRedeliveryMaxInterval          = time.Minute
	defaultActivityPubClientCacheSize       = 100
	defaultActivityPubClientCacheExpiration = 10 * time.Minute
	defaultActivityPubIRICacheSize          = 100
	defaultActivityPubIRICacheExpiration    = time.Hour
	defaultFollowAuthType                   = acceptAllPolicy
	defaultInviteWitnessAuthType            = acceptAllPolicy
	defaultWitnessPolicyCacheExpiration     = 30 * time.Second
	defaultDataURIMediaType                 = datauri.MediaTypeDataURIGzipBase64
	defaultAllowedOriginsCacheExpiration    = time.Minute

	defaultTracingServiceName = "orb"

	opQueueDefaultTaskMonitorInterval   = 10 * time.Second
	opQueueDefaultTaskExpiration        = 30 * time.Second
	opQueueDefaultMaxOperationsToRepost = 10000
	opQueueDefaultOperationLifespan     = 24 * time.Hour

	splitRequestTokenLength = 2
	vctReadTokenKey         = "vct-read"
	vctWriteTokenKey        = "vct-write"

	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the orb-server instance on. Format: HostName:Port."
	hostURLEnvKey        = "ORB_HOST_URL"

	syncTimeoutFlagName  = "sync-timeout"
	syncTimeoutEnvKey    = "ORB_SYNC_TIMEOUT"
	syncTimeoutFlagUsage = "Total time in seconds to resolve config values." +
		" Alternatively, this can be set with the following environment variable: " + syncTimeoutEnvKey

	vctProofMonitoringIntervalFlagName  = "vct-proof-monitoring-interval"
	vctProofMonitoringIntervalEnvKey    = "VCT_PROOF_MONITORING_INTERVAL"
	vctProofMonitoringIntervalFlagUsage = "The interval in which VCTs are monitored to ensure that proofs are anchored. " +
		"Defaults to 10s if not set. " +
		commonEnvVarUsageText + vctProofMonitoringIntervalEnvKey

	vctProofMonitoringExpiryPeriodFlagName  = "vct-proof-monitoring-expiry-period"
	vctProofMonitoringExpiryPeriodEnvKey    = "VCT_PROOF_MONITORING_EXPIRY_PERIOD"
	vctProofMonitoringExpiryPeriodFlagUsage = "Monitoring service will keep checking for this period of time for proof to be included(default 1h). " +
		commonEnvVarUsageText + vctProofMonitoringExpiryPeriodEnvKey

	vctLogMonitoringIntervalFlagName  = "vct-log-monitoring-interval"
	vctLogMonitoringIntervalEnvKey    = "VCT_LOG_MONITORING_INTERVAL"
	vctLogMonitoringIntervalFlagUsage = "The interval in which VCT logs are monitored to ensure that they are consistent. " +
		"Defaults to 10s if not set. " +
		commonEnvVarUsageText + vctLogMonitoringIntervalEnvKey

	vctLogMonitoringMaxTreeSizeFlagName  = "vct-log-monitoring-max-tree-size"
	vctLogMonitoringMaxTreeSizeEnvKey    = "VCT_LOG_MONITORING_MAX_TREE_SIZE"
	vctLogMonitoringMaxTreeSizeFlagUsage = "The maximum tree size for which new VCT logs will be re-constructed in order to verify STH. " +
		"Defaults to 50000 if not set. " +
		commonEnvVarUsageText + vctLogMonitoringMaxTreeSizeEnvKey

	vctLogMonitoringGetEntriesRangeFlagName  = "vct-log-monitoring-get-entries-range"
	vctLogMonitoringGetEntriesRangeEnvKey    = "VCT_LOG_MONITORING_GET_ENTRIES_RANGE"
	vctLogMonitoringGetEntriesRangeFlagUsage = "The maximum number of entries to be retrieved from VCT log in one attempt. " +
		"Defaults to 1000 if not set. Has to be less or equal than 1000 due to VCT limitation." +
		commonEnvVarUsageText + vctLogMonitoringGetEntriesRangeEnvKey

	vctLogEntriesStoreEnabledFlagName  = "vct-log-entries-store-enabled"
	vctLogEntriesStoreEnabledEnvKey    = "VCT_LOG_ENTRIES_STORE_ENABLED"
	vctLogEntriesStoreEnabledFlagUsage = "Enables storing of log entries during log monitoring. " +
		"Defaults to false if not set. " +
		commonEnvVarUsageText + vctLogEntriesStoreEnabledEnvKey

	anchorStatusMonitoringIntervalFlagName  = "anchor-status-monitoring-interval"
	anchorStatusMonitoringIntervalEnvKey    = "ANCHOR_STATUS_MONITORING_INTERVAL"
	anchorStatusMonitoringIntervalFlagUsage = "The interval in which 'in-process' anchors are monitored to ensure that they will be " +
		"witnessed(completed) as per policy. Defaults to 5s if not set. " +
		commonEnvVarUsageText + anchorStatusMonitoringIntervalEnvKey

	anchorStatusInProcessGracePeriodFlagName  = "anchor-status-in-process-grace-period"
	anchorStatusInProcessGracePeriodEnvKey    = "ANCHOR_STATUS_IN_PROCESS_GRACE_PERIOD"
	anchorStatusInProcessGracePeriodFlagUsage = "The period in which witnesses will not be re-selected for 'in-process' anchors." +
		"Defaults to 30s if not set. " +
		commonEnvVarUsageText + anchorStatusInProcessGracePeriodEnvKey

	externalEndpointFlagName      = "external-endpoint"
	externalEndpointFlagShorthand = "e"
	externalEndpointFlagUsage     = "External endpoint that clients use to invoke services." +
		" This endpoint is used to generate IDs of anchor credentials and ActivityPub objects and" +
		" should be resolvable by external clients. Format: HostName[:Port]."
	externalEndpointEnvKey = "ORB_EXTERNAL_ENDPOINT"

	serviceIDFlagName  = "service-id"
	serviceIDFlagUsage = "The ID of the ActivityPub service." +
		" By default, the ID is composed of the external endpoint appended with /services/orb, " +
		" but it can also be set to a did:web DID, e.g. did:web:alice.example.com:services:anchor."
	serviceIDEnvKey = "ORB_SERVICE_ID"

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

	mqObserverPoolFlagName      = "mq-observer-pool"
	mqObserverPoolFlagShorthand = "B"
	mqObserverPoolEnvKey        = "MQ_OBSERVER_POOL"
	mqObserverPoolFlagUsage     = "The size of the observer queue subscriber pool. If not specified then the default size will be used. " +
		commonEnvVarUsageText + mqObserverPoolEnvKey

	mqOutboxPoolFlagName  = "mq-outbox-pool"
	mqOutboxPoolEnvKey    = "MQ_OUTBOX_POOL"
	mqOutboxPoolFlagUsage = "The size of the outbox queue subscriber pool. If not specified then the default size is used. " +
		commonEnvVarUsageText + mqOutboxPoolEnvKey

	mqInboxPoolFlagName  = "mq-inbox-pool"
	mqInboxPoolEnvKey    = "MQ_INBOX_POOL"
	mqInboxPoolFlagUsage = "The size of the inbox queue subscriber pool. If not specified then the default size is used. " +
		commonEnvVarUsageText + mqInboxPoolEnvKey

	mqMaxConnectionChannelsFlagName      = "mq-max-connection-channels"
	mqMaxConnectionChannelsFlagShorthand = "C"
	mqMaxConnectionChannelsEnvKey        = "MQ_MAX_CONNECTION_CHANNELS"
	mqMaxConnectionChannelsFlagUsage     = "The maximum number of channels per connection. " +
		commonEnvVarUsageText + mqMaxConnectionChannelsEnvKey

	mqPublisherChannelPoolSizeFlagName  = "mq-publisher-channel-pool-size"
	mqPublisherChannelPoolSizeEnvKey    = "MQ_PUBLISHER_POOL"
	mqPublisherChannelPoolSizeFlagUsage = "The size of a channel pool for an AMQP publisher (default is 25). " +
		"If set to 0 then a channel pool is not used and a new channel is opened/closed for every publish to a queue." +
		commonEnvVarUsageText + mqPublisherChannelPoolSizeEnvKey

	mqPublisherConfirmDeliveryFlagName  = "mq-publisher-confirm-delivery"
	mqPublisherConfirmDeliveryEnvKey    = "MQ_PUBLISHER_CONFIRM_DELIVERY"
	mqPublisherConfirmDeliveryFlagUsage = "Turns on delivery confirmation of published messages (default is true). " +
		"If set to true then the publisher waits until a confirmation is received from the AMQP server to guarantee " +
		"that the message is delivered." +
		commonEnvVarUsageText + mqPublisherConfirmDeliveryEnvKey

	mqConnectMaxRetriesFlagName  = "mq-connect-max-retries"
	mqConnectMaxRetriesEnvKey    = "MQ_CONNECT_MAX_RETRIES"
	mqConnectMaxRetriesFlagUsage = "The maximum number of retries to connect to an AMQP service (default is 25). " +
		commonEnvVarUsageText + mqConnectMaxRetriesEnvKey

	mqRedeliveryMaxAttemptsFlagName  = "mq-redelivery-max-attempts"
	mqRedeliveryMaxAttemptsEnvKey    = "MQ_REDELIVERY_MAX_ATTEMPTS"
	mqRedeliveryMaxAttemptsFlagUsage = "The maximum number of redelivery attempts for a failed message (default is 30). " +
		commonEnvVarUsageText + mqRedeliveryMaxAttemptsEnvKey

	mqRedeliveryInitialIntervalFlagName  = "mq-redelivery-initial-interval"
	mqRedeliveryInitialIntervalEnvKey    = "MQ_REDELIVERY_INITIAL_INTERVAL"
	mqRedeliveryInitialIntervalFlagUsage = "The delay for the initial redelivery attempt (default is 2s). " +
		commonEnvVarUsageText + mqRedeliveryInitialIntervalEnvKey

	mqRedeliveryMultiplierFlagName  = "mq-redelivery-multiplier"
	mqRedeliveryMultiplierEnvKey    = "MQ_REDELIVERY_MULTIPLIER"
	mqRedeliveryMultiplierFlagUsage = "The multiplier for a redelivery attempt. For example, if set to 1.5 and " +
		"the previous redelivery interval was 2s then the next redelivery interval is set 3s (default is 1.5). " +
		commonEnvVarUsageText + mqRedeliveryMultiplierEnvKey

	mqRedeliveryMaxIntervalFlagName  = "mq-redelivery-max-interval"
	mqRedeliveryMaxIntervalEnvKey    = "MQ_REDELIVERY_MAX_INTERVAL"
	mqRedeliveryMaxIntervalFlagUsage = "The maximum delay for a redelivery (default is 1m). " +
		commonEnvVarUsageText + mqRedeliveryMaxIntervalEnvKey

	mqOPQueuePoolFlagName      = "mq-opqueue-pool"
	mqOPQueuePoolFlagShorthand = "O"
	mqOPQueuePoolEnvKey        = "MQ_OPQUEUE_POOL"
	mqOPQueuePoolFlagUsage     = "The size of the operation queue subscriber pool. If <=1 then a pool will not be created. " +
		commonEnvVarUsageText + mqOPQueuePoolEnvKey

	mqAnchorLinksetPoolFlagName  = "mq-anchor-linkset-pool"
	mqAnchorLinksetPoolEnvKey    = "MQ_ANCHOR_LINKSET_POOL"
	mqAnchorLinksetPoolFlagUsage = "The size of the anchor-linkset subscriber pool. If <=1 then a pool will not be created. " +
		commonEnvVarUsageText + mqAnchorLinksetPoolEnvKey

	opQueueTaskMonitorIntervalFlagName  = "op-queue-task-monitor-interval"
	opQueueTaskMonitorIntervalEnvKey    = "OP_QUEUE_TASK_MONITOR_INTERVAL"
	opQueueTaskMonitorIntervalFlagUsage = "The interval (period) in which operation queue tasks from other server " +
		" instances are monitored (default is 10s). " + commonEnvVarUsageText + opQueueTaskMonitorIntervalEnvKey

	opQueueTaskExpirationFlagName  = "op-queue-task-expiration"
	opQueueTaskExpirationEnvKey    = "OP_QUEUE_TASK_EXPIRATION"
	opQueueTaskExpirationFlagUsage = "The maximum time that an operation queue task can exist in the database before " +
		"it is considered to have expired. At which point, any other server instance may delete the task and " +
		"repost the operations associated with the task to the queue so that they are processed by another " +
		"Orb instance (default is 30s). " +
		commonEnvVarUsageText + opQueueTaskExpirationEnvKey

	opQueueMaxOperationsToRepostFlagName  = "op-queue-max-ops-to-repost"
	opQueueMaxOperationsToRepostEnvKey    = "OP_QUEUE_MAX_OPS_TO_REPOST"
	opQueueMaxOperationsToRepostFlagUsage = "The maximum number of operations to repost to the queue after an instance dies (default is 10000). " +
		commonEnvVarUsageText + opQueueMaxOperationsToRepostEnvKey

	opQueueOperationLifespanFlagName  = "op-queue-operation-lifespan"
	opQueueOperationLifespanEnvKey    = "OP_QUEUE_OPERATION_LIFESPAN"
	opQueueOperationLifespanFlagUsage = "The maximum time that an operation can exist in the database before it is deleted (default is 24h). " +
		commonEnvVarUsageText + opQueueOperationLifespanEnvKey

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

	databaseTimeoutFlagName  = "database-timeout"
	databaseTimeoutEnvKey    = "DATABASE_TIMEOUT"
	databaseTimeoutFlagUsage = "The timeout for database requests. For example, '30s' for a 30 second timeout. " +
		"Currently this setting only applies if you're using MongoDB. " +
		commonEnvVarUsageText + databaseTimeoutEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMongoDBOption = "mongodb"

	anchorCredentialDomainFlagName      = "anchor-credential-domain"
	anchorCredentialDomainEnvKey        = "ANCHOR_CREDENTIAL_DOMAIN"
	anchorCredentialDomainFlagShorthand = "d"
	anchorCredentialDomainFlagUsage     = "Anchor credential domain (required). " +
		commonEnvVarUsageText + anchorCredentialDomainEnvKey

	allowedOriginsFlagName      = "allowed-origins"
	allowedOriginsEnvKey        = "ALLOWED_ORIGINS"
	allowedOriginsFlagShorthand = "o"
	allowedOriginsFlagUsage     = "Allowed origins for this did method. " + commonEnvVarUsageText + allowedOriginsEnvKey

	allowedOriginsCacheExpirationFlagName  = "allowed-origins-cache-expiration"
	allowedOriginsCacheExpirationEnvKey    = "ALLOWED_ORIGINS_CACHE_EXPIRATION"
	allowedOriginsCacheExpirationFlagUsage = "The expiration time of the allowed origins cache. " +
		commonEnvVarUsageText + allowedOriginsCacheExpirationEnvKey

	allowedDIDWebDomainsFlagName  = "allowed-did-web-domains"
	allowedDIDWebDomainsEnvKey    = "ALLOWED_DID_WEB_DOMAINS"
	allowedDIDWebDomainsFlagUsage = "Allowed domains for did:web method resolution. " + commonEnvVarUsageText + allowedDIDWebDomainsEnvKey

	maxWitnessDelayFlagName      = "max-witness-delay"
	maxWitnessDelayEnvKey        = "MAX_WITNESS_DELAY"
	maxWitnessDelayFlagShorthand = "w"
	maxWitnessDelayFlagUsage     = "Maximum witness response time (default 10m). " + commonEnvVarUsageText + maxWitnessDelayEnvKey

	maxClockSkewFlagName  = "max-clock-skew"
	maxClockSkewEnvKey    = "MAX_CLOCK_SKEW"
	maxClockSkewFlagUsage = "Maximum clock skew (default 1m). " + commonEnvVarUsageText + maxClockSkewEnvKey

	witnessStoreExpiryPeriodFlagName  = "witness-store-expiry-period"
	witnessStoreExpiryPeriodEnvKey    = "WITNESS_STORE_EXPIRY_PERIOD"
	witnessStoreExpiryPeriodFlagUsage = "Witness store expiry period has to be greater than " +
		"maximum witness response time + clock skew time" +
		"(default 12m). " + commonEnvVarUsageText + witnessStoreExpiryPeriodEnvKey

	signWithLocalWitnessFlagName      = "sign-with-local-witness"
	signWithLocalWitnessEnvKey        = "SIGN_WITH_LOCAL_WITNESS"
	signWithLocalWitnessFlagShorthand = "f"
	signWithLocalWitnessFlagUsage     = "Always sign with local witness flag (default true). " +
		commonEnvVarUsageText + signWithLocalWitnessEnvKey

	discoveryDomainsFlagName  = "discovery-domains"
	discoveryDomainsEnvKey    = "DISCOVERY_DOMAINS"
	discoveryDomainsFlagUsage = "Discovery domains. " + commonEnvVarUsageText + discoveryDomainsEnvKey

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

	enableUnpublishedOperationStoreFlagName = "enable-unpublished-operation-store"
	enableUnpublishedOperationStoreEnvKey   = "UNPUBLISHED_OPERATION_STORE_ENABLED"
	enableUnpublishedOperationStoreUsage    = `Set to "true" to enable un-published operation store. ` +
		`Used to enable including unpublished operations when resolving documents.` +
		commonEnvVarUsageText + enableUnpublishedOperationStoreEnvKey

	unpublishedOperationStoreOperationTypesFlagName = "unpublished-operation-store-operation-types"
	unpublishedOperationStoreOperationTypesEnvKey   = "UNPUBLISHED_OPERATION_STORE_OPERATION_TYPES"
	unpublishedOperationStoreOperationTypesUsage    = `Comma-separated list of operation types. ` +
		`Used if unpublished operation store is enabled.` +
		commonEnvVarUsageText + unpublishedOperationStoreOperationTypesEnvKey

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

	clientAuthTokensDefFlagName  = "client-auth-tokens-def"
	clientAuthTokensDefFlagUsage = "Client authorization token definitions."
	clientAuthTokensDefEnvKey    = "ORB_CLIENT_AUTH_TOKENS_DEF"

	clientAuthTokensFlagName  = "client-auth-tokens"
	clientAuthTokensFlagUsage = "Client authorization tokens."
	clientAuthTokensEnvKey    = "ORB_CLIENT_AUTH_TOKENS"

	activityPubPageSizeFlagName      = "activitypub-page-size"
	activityPubPageSizeFlagShorthand = "P"
	activityPubPageSizeEnvKey        = "ACTIVITYPUB_PAGE_SIZE"
	activityPubPageSizeFlagUsage     = "The maximum page size for an ActivityPub collection or ordered collection. " +
		commonEnvVarUsageText + activityPubPageSizeEnvKey

	enableVCTFlagName  = "vct-enabled"
	enableVCTFlagUsage = "Indicates if Orb server has VCT log configured."
	enabledVCTEnvKey   = "VCT_ENABLED"

	devModeEnabledFlagName = "enable-dev-mode"
	devModeEnabledEnvKey   = "DEV_MODE_ENABLED"
	devModeEnabledUsage    = `Set to "true" to enable dev mode. ` +
		commonEnvVarUsageText + devModeEnabledEnvKey

	maintenanceModeEnabledFlagName = "enable-maintenance-mode"
	maintenanceModeEnabledEnvKey   = "MAINTENANCE_MODE_ENABLED"
	maintenanceModeEnabledUsage    = `Set to "true" to enable maintenance mode. ` +
		commonEnvVarUsageText + maintenanceModeEnabledEnvKey

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

	httpTimeoutFlagName  = "http-timeout"
	httpTimeoutEnvKey    = "HTTP_TIMEOUT"
	httpTimeoutFlagUsage = "The timeout for http requests. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + httpTimeoutEnvKey

	httpDialTimeoutFlagName  = "http-dial-timeout"
	httpDialTimeoutEnvKey    = "HTTP_DIAL_TIMEOUT"
	httpDialTimeoutFlagUsage = "The timeout for http dial. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + httpDialTimeoutEnvKey

	anchorSyncIntervalFlagName      = "sync-interval"
	anchorSyncIntervalFlagShorthand = "S"
	anchorSyncIntervalEnvKey        = "ANCHOR_EVENT_SYNC_INTERVAL"
	anchorSyncIntervalFlagUsage     = "The interval in which anchor events are synchronized with other services that " +
		"this service is following. Defaults to 1m if not set. " +
		commonEnvVarUsageText + anchorSyncIntervalEnvKey

	anchorSyncMaxActivitiesFlagName  = "sync-max-activities"
	anchorSyncMaxActivitiesEnvKey    = "ANCHOR_EVENT_SYNC_MAX_ACTIVITIES"
	anchorSyncMaxActivitiesFlagUsage = "The maximum number of activities to be synchronized in a single task run. Defaults to 500 if not set. " +
		commonEnvVarUsageText + anchorSyncMaxActivitiesEnvKey

	anchorSyncAcceleratedIntervalFlagName = "sync-accelerated-interval"
	anchorSyncAcceleratedIntervalEnvKey   = "ANCHOR_EVENT_SYNC_ACCELERATED_INTERVAL"
	anchorSyncNextIntervalFlagUsage       = "The interval in which to run the activity sync task after the maximum number of activities " +
		"(specified by sync-max-activities) have been processed for the current task run. This should be smaller than the default interval " +
		"in order to accelerate processing. Defaults to 15s if not set. " +
		commonEnvVarUsageText + anchorSyncAcceleratedIntervalEnvKey

	anchorSyncMinActivityAgeFlagName  = "sync-min-activity-age"
	anchorSyncMinActivityAgeEnvKey    = "ANCHOR_EVENT_SYNC_MIN_ACTIVITY_AGE"
	anchorSyncMinActivityAgeFlagUsage = "The minimum age of an activity to be synchronized. The activity will be " +
		"processed only if its age is greater than this value. Defaults to 10m if not set. " +
		commonEnvVarUsageText + anchorSyncMinActivityAgeEnvKey

	activityPubClientCacheSizeFlagName  = "apclient-cache-size"
	activityPubClientCacheSizeEnvKey    = "ACTIVITYPUB_CLIENT_CACHE_SIZE"
	activityPubClientCacheSizeFlagUsage = "The maximum size of an ActivityPub service and public key cache. " +
		commonEnvVarUsageText + activityPubClientCacheSizeEnvKey

	activityPubClientCacheExpirationFlagName  = "apclient-cache-Expiration"
	activityPubClientCacheExpirationEnvKey    = "ACTIVITYPUB_CLIENT_CACHE_EXPIRATION"
	activityPubClientCacheExpirationFlagUsage = "The expiration time of an ActivityPub service and public key cache. " +
		commonEnvVarUsageText + activityPubClientCacheExpirationEnvKey

	activityPubIRICacheSizeFlagName  = "apiri-cache-size"
	activityPubIRICacheSizeEnvKey    = "ACTIVITYPUB_IRI_CACHE_SIZE"
	activityPubIRICacheSizeFlagUsage = "The maximum size of an ActivityPub actor IRI cache. " +
		commonEnvVarUsageText + activityPubIRICacheSizeEnvKey

	activityPubIRICacheExpirationFlagName  = "apiri-cache-Expiration"
	activityPubIRICacheExpirationEnvKey    = "ACTIVITYPUB_IRI_CACHE_EXPIRATION"
	activityPubIRICacheExpirationFlagUsage = "The expiration time of an ActivityPub actor IRI cache. " +
		commonEnvVarUsageText + activityPubIRICacheExpirationEnvKey

	serverIdleTimeoutFlagName  = "server-idle-timeout"
	serverIdleTimeoutEnvKey    = "SERVER_IDLE_TIMEOUT"
	serverIdleTimeoutFlagUsage = "The timeout for server idle timeout. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + serverIdleTimeoutEnvKey

	serverReadHeaderTimeoutFlagName  = "server-read-header-timeout"
	serverReadHeaderTimeoutEnvKey    = "SERVER_READ_HEADER_TIMEOUT"
	serverReadHeaderTimeoutFlagUsage = "The timeout for server read header timeout. For example, '30s' for a 30 second timeout. " +
		commonEnvVarUsageText + serverReadHeaderTimeoutEnvKey

	witnessPolicyCacheExpirationFlagName  = "witness-policy-cache-expiration"
	witnessPolicyCacheExpirationEnvKey    = "WITNESS_POLICY_CACHE_EXPIRATION"
	witnessPolicyCacheExpirationFlagUsage = "The expiration time of witness policy cache. " +
		commonEnvVarUsageText + witnessPolicyCacheExpirationEnvKey

	dataURIMediaTypeFlagName  = "anchor-data-uri-media-type"
	dataURIMediaTypeEnvKey    = "ANCHOR_DATA_URI_MEDIA_TYPE"
	dataURIMediaTypeFlagUsage = "The media type for data URIs in an anchor Linkset. Possible values are " +
		"'application/json' and 'application/gzip;base64'. If 'application/json' is specified then the content of the data URIs " +
		"in the anchor LInkset are encoded as an escaped JSON string. If 'application/gzip;base64' is specified then the content is " +
		"compressed with gzip and base64 encoded (default is 'application/gzip;base64')." +
		commonEnvVarUsageText + dataURIMediaTypeEnvKey

	sidetreeProtocolVersionsFlagName = "sidetree-protocol-versions"
	sidetreeProtocolVersionsEnvKey   = "SIDETREE_PROTOCOL_VERSIONS"
	sidetreeProtocolVersionsUsage    = `Comma-separated list of sidetree protocol versions. ` +
		commonEnvVarUsageText + sidetreeProtocolVersionsEnvKey

	currentSidetreeProtocolVersionFlagName = "current-sidetree-protocol-version"
	currentSidetreeProtocolVersionEnvKey   = "CURRENT_SIDETREE_PROTOCOL_VERSION"
	currentSidetreeProtocolVersionUsage    = `One of available sidetree protocol versions.  ` +
		`Defaults to latest Sidetree protocol version. ` +
		commonEnvVarUsageText + currentSidetreeProtocolVersionEnvKey

	requestTokensFlagName  = "request-tokens"
	requestTokensEnvKey    = "ORB_REQUEST_TOKENS" //nolint: gosec
	requestTokensFlagUsage = "Tokens used for http request supported tokens (vct-read and vct-write) " +
		commonEnvVarUsageText + requestTokensEnvKey

	metricsProviderFlagName         = "metrics-provider-name"
	metricsProviderEnvKey           = "ORB_METRICS_PROVIDER_NAME"
	allowedMetricsProviderFlagUsage = "The metrics provider name (for example: 'prometheus' etc.). " +
		commonEnvVarUsageText + metricsProviderEnvKey

	promHTTPURLFlagName             = "prom-http-url"
	promHTTPURLEnvKey               = "ORB_PROM_HTTP_URL"
	allowedPromHTTPURLFlagNameUsage = "URL that exposes the prometheus metrics endpoint. Format: HostName:Port. "

	tracingProviderFlagName  = "tracing-provider"
	tracingProviderEnvKey    = "ORB_TRACING_PROVIDER"
	tracingProviderFlagUsage = "The tracing provider (for example, JAEGER). " +
		commonEnvVarUsageText + tracingProviderEnvKey

	tracingCollectorURLFlagName  = "tracing-collector-url"
	tracingCollectorURLEnvKey    = "ORB_TRACING_COLLECTOR_URL"
	tracingCollectorURLFlagUsage = "The URL of the tracing collector (for example, Jaeger). " +
		commonEnvVarUsageText + tracingCollectorURLEnvKey

	tracingServiceNameFlagName  = "tracing-service-name"
	tracingServiceNameEnvKey    = "ORB_TRACING_SERVICE_NAME"
	tracingServiceNameFlagUsage = "The name of the tracing service (for example, orb1). " +
		commonEnvVarUsageText + tracingServiceNameEnvKey
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
	http                             *httpParams
	sidetree                         *sidetreeParams
	apServiceParams                  *apServiceParams
	discoveryDomain                  string
	dataURIMediaType                 datauri.MediaType
	batchWriterTimeout               time.Duration
	cas                              *casParams
	mqParams                         *mqParams
	opQueueParams                    *opqueue.Config
	dbParameters                     *dbParameters
	logLevel                         string
	methodContext                    []string
	baseEnabled                      bool
	allowedOrigins                   []string
	allowedOriginsCacheExpiration    time.Duration
	anchorCredentialParams           *anchorCredentialParams
	discovery                        *discoveryParams
	witnessProof                     *witnessProofParams
	syncTimeout                      uint64
	didDiscoveryEnabled              bool
	unpublishedOperations            *unpublishedOperationsStoreParams
	resolveFromAnchorOrigin          bool
	verifyLatestFromAnchorOrigin     bool
	activityPub                      *activityPubParams
	auth                             *authParams
	enableDevMode                    bool
	enableMaintenanceMode            bool
	enableVCT                        bool
	nodeInfoRefreshInterval          time.Duration
	contextProviderURLs              []string
	dataExpiryCheckInterval          time.Duration
	taskMgrCheckInterval             time.Duration
	vct                              *vctParams
	anchorStatusMonitoringInterval   time.Duration
	anchorStatusInProcessGracePeriod time.Duration
	witnessPolicyCacheExpiration     time.Duration
	kmsParams                        *kmsParameters
	requestTokens                    map[string]string
	allowedDIDWebDomains             []*url.URL
	observability                    *observabilityParams
}

type observabilityParams struct {
	metrics metricsParams
	tracing tracingParams
}

type metricsParams struct {
	providerName string
	url          string
}

type tracingParams struct {
	provider     tracing.ProviderType
	collectorURL string
	serviceName  string
	enabled      bool
}

// apServiceParams contains accessor functions for various
// service parameters.
type apServiceParams struct {
	serviceEndpoint func() *url.URL
	serviceIRI      func() *url.URL
	publicKeyIRI    func() string
}

type anchorCredentialParams struct {
	domain string
	issuer string
	url    string
}

type dbParameters struct {
	databaseType    string
	databaseURL     string
	databasePrefix  string
	databaseTimeout time.Duration
}

type kmsParameters struct {
	kmsType                  kmsMode
	kmsEndpoint              string
	kmsRegion                string
	kmsSecretsDatabaseType   string
	kmsSecretsDatabaseURL    string
	kmsSecretsDatabasePrefix string
	vcSignActiveKeyID        string
	vcSignPrivateKeys        map[string]string
	vcSignKeysID             []string
	httpSignActiveKeyID      string
	httpSignPrivateKey       map[string]string
	secretLockKeyPath        string
}

func getKmsParameters(cmd *cobra.Command) (*kmsParameters, error) {
	kmsTypeStr, err := cmdutil.GetUserSetVarFromString(cmd, kmsTypeFlagName, kmsTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	kmsType := kmsMode(kmsTypeStr)

	if !supportedKmsType(kmsType) {
		return nil, fmt.Errorf("unsupported kms type: %s", kmsType)
	}

	kmsEndpoint := cmdutil.GetUserSetOptionalVarFromString(cmd, kmsEndpointFlagName, kmsEndpointEnvKey)

	kmsRegion := cmdutil.GetUserSetOptionalVarFromString(cmd, kmsRegionFlagName, kmsRegionEnvKey)

	secretLockKeyPath := cmdutil.GetUserSetOptionalVarFromString(cmd, secretLockKeyPathFlagName, secretLockKeyPathEnvKey)
	keyDatabaseType, err := cmdutil.GetUserSetVarFromString(cmd, kmsSecretsDatabaseTypeFlagName,
		kmsSecretsDatabaseTypeEnvKey, kmsType != kmsLocal)
	if err != nil {
		return nil, err
	}
	keyDatabaseURL := cmdutil.GetUserSetOptionalVarFromString(cmd, kmsSecretsDatabaseURLFlagName,
		kmsSecretsDatabaseURLEnvKey)
	keyDatabasePrefix := cmdutil.GetUserSetOptionalVarFromString(cmd, kmsSecretsDatabasePrefixFlagName,
		kmsSecretsDatabasePrefixEnvKey)

	vcSignActiveKeyID := cmdutil.GetUserSetOptionalVarFromString(cmd, vcSignActiveKeyIDFlagName, vcSignActiveKeyIDEnvKey)
	vcSignPrivateKeys, err := getPrivateKeys(cmd, vcSignPrivateKeysFlagName, vcSignPrivateKeysEnvKey)
	if err != nil {
		return nil, fmt.Errorf("vc sign private keys: %w", err)
	}
	if len(vcSignPrivateKeys) > 0 {
		if _, ok := vcSignPrivateKeys[vcSignActiveKeyID]; !ok {
			return nil, fmt.Errorf("vc sign active key id %s not exist in vc private keys", vcSignActiveKeyID)
		}
	}
	vcSignKeysID := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, vcSignKeysIDFlagName, vcSignKeysIDEnvKey)

	httpSignActiveKeyID := cmdutil.GetUserSetOptionalVarFromString(cmd, httpSignActiveKeyIDFlagName, httpSignActiveKeyIDEnvKey)
	httpSignPrivateKey, err := getPrivateKeys(cmd, httpSignPrivateKeyFlagName, httpSignPrivateKeyEnvKey)
	if err != nil {
		return nil, fmt.Errorf("http sign private keys: %w", err)
	}
	if len(httpSignPrivateKey) > 0 {
		if len(httpSignPrivateKey) > 1 {
			return nil, fmt.Errorf("http sign private key include more than one key")
		}

		if _, ok := httpSignPrivateKey[httpSignActiveKeyID]; !ok {
			return nil, fmt.Errorf("http sign active key id %s not exist in http private key", httpSignActiveKeyID)
		}
	}

	return &kmsParameters{
		kmsType:                  kmsType,
		kmsEndpoint:              kmsEndpoint,
		kmsRegion:                kmsRegion,
		vcSignActiveKeyID:        vcSignActiveKeyID,
		vcSignPrivateKeys:        vcSignPrivateKeys,
		vcSignKeysID:             vcSignKeysID,
		httpSignActiveKeyID:      httpSignActiveKeyID,
		httpSignPrivateKey:       httpSignPrivateKey,
		secretLockKeyPath:        secretLockKeyPath,
		kmsSecretsDatabaseType:   keyDatabaseType,
		kmsSecretsDatabaseURL:    keyDatabaseURL,
		kmsSecretsDatabasePrefix: keyDatabasePrefix,
	}, nil
}

func supportedKmsType(kmsType kmsMode) bool {
	if kmsType != kmsLocal && kmsType != kmsWeb && kmsType != kmsAWS {
		return false
	}

	return true
}

//nolint:funlen,gocyclo
func getOrbParameters(cmd *cobra.Command) (*orbParameters, error) {
	httpParams, err := getHTTPParams(cmd)
	if err != nil {
		return nil, err
	}

	observabilityParams, err := getObservabilityParams(cmd)
	if err != nil {
		return nil, err
	}

	serviceID, err := cmdutil.GetUserSetVarFromString(cmd, serviceIDFlagName, serviceIDEnvKey, true)
	if err != nil {
		return nil, err
	}

	discoveryDomain, err := cmdutil.GetUserSetVarFromString(cmd, discoveryDomainFlagName, discoveryDomainEnvKey, true)
	if err != nil {
		return nil, err
	}

	casParams, err := getCASParams(cmd)
	if err != nil {
		return nil, err
	}

	mqParams, err := getMQParameters(cmd)
	if err != nil {
		return nil, err
	}

	batchWriterTimeoutStr, err := cmdutil.GetUserSetVarFromString(cmd, batchWriterTimeoutFlagName, batchWriterTimeoutEnvKey, true)
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

	opQueueParams, err := getOpQueueParameters(cmd, mqParams)
	if err != nil {
		return nil, err
	}

	witnessProofParams, err := getWitnessProofParams(cmd)
	if err != nil {
		return nil, err
	}

	syncTimeout, err := cmdutil.GetUInt64(cmd, syncTimeoutFlagName, syncTimeoutEnvKey, defaultSyncTimeout)
	if err != nil {
		return nil, err
	}

	didDiscoveryEnabled, err := cmdutil.GetBool(cmd, enableDidDiscoveryFlagName, enableDidDiscoveryEnvKey,
		defaultDidDiscoveryEnabled)
	if err != nil {
		return nil, err
	}

	enableVCT, err := cmdutil.GetBool(cmd, enableVCTFlagName, enabledVCTEnvKey, defaultVCTEnabled)
	if err != nil {
		return nil, err
	}

	enableDevMode, err := cmdutil.GetBool(cmd, devModeEnabledFlagName, devModeEnabledEnvKey, defaultDevModeEnabled)
	if err != nil {
		return nil, err
	}

	enableMaintenanceMode, err := cmdutil.GetBool(cmd, maintenanceModeEnabledFlagName, maintenanceModeEnabledEnvKey,
		defaultMaintenanceModeEnabled)
	if err != nil {
		return nil, err
	}

	unpublishedOperationsParams, err := getUnpublishedOperationsParams(cmd)
	if err != nil {
		return nil, err
	}

	resolveFromAnchorOrigin, err := cmdutil.GetBool(cmd, resolveFromAnchorOriginFlagName, resolveFromAnchorOriginEnvKey,
		defaultResolveFromAnchorOrigin)
	if err != nil {
		return nil, err
	}

	verifyLatestFromAnchorOrigin, err := cmdutil.GetBool(cmd, verifyLatestFromAnchorOriginFlagName, verifyLatestFromAnchorOriginEnvKey,
		defaultVerifyLatestFromAnchorOrigin)
	if err != nil {
		return nil, err
	}

	sidetreeParams, err := getSidetreeParams(cmd)
	if err != nil {
		return nil, err
	}

	kmsParams, err := getKmsParameters(cmd)
	if err != nil {
		return nil, err
	}

	dbParams, err := getDBParameters(cmd)
	if err != nil {
		return nil, err
	}

	loggingLevel, err := cmdutil.GetUserSetVarFromString(cmd, LogLevelFlagName, LogLevelEnvKey, true)
	if err != nil {
		return nil, err
	}

	allowedOrigins, err := cmdutil.GetUserSetVarFromArrayString(cmd, allowedOriginsFlagName, allowedOriginsEnvKey, true)
	if err != nil {
		return nil, err
	}

	allowedOriginsCacheExpiration, err := cmdutil.GetDuration(cmd, allowedOriginsCacheExpirationFlagName,
		allowedOriginsCacheExpirationEnvKey, defaultAllowedOriginsCacheExpiration)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", allowedOriginsCacheExpirationFlagName, err)
	}

	allowedDIDWebDomains, err := getAllowedDIDWebDomains(cmd)
	if err != nil {
		return nil, err
	}

	dataURIMediaType, err := cmdutil.GetUserSetVarFromString(cmd, dataURIMediaTypeFlagName, dataURIMediaTypeEnvKey, true)
	if err != nil {
		return nil, err
	}

	if dataURIMediaType == "" {
		dataURIMediaType = defaultDataURIMediaType
	}

	discoveryParams, err := getDiscoveryParams(cmd)
	if err != nil {
		return nil, err
	}

	authParams, err := getAuthParams(cmd)
	if err != nil {
		return nil, err
	}

	activityPubParams, err := getActivityPubParams(cmd)
	if err != nil {
		return nil, err
	}

	nodeInfoRefreshInterval, err := cmdutil.GetDuration(cmd, nodeInfoRefreshIntervalFlagName,
		nodeInfoRefreshIntervalEnvKey, defaultNodeInfoRefreshInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", nodeInfoRefreshIntervalFlagName, err)
	}

	contextProviderURLs, err := cmdutil.GetUserSetVarFromArrayString(cmd, contextProviderFlagName, contextProviderEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", contextProviderFlagName, err)
	}

	dataExpiryCheckInterval, err := cmdutil.GetDuration(cmd, dataExpiryCheckIntervalFlagName,
		dataExpiryCheckIntervalEnvKey, defaultDataExpiryCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dataExpiryCheckIntervalFlagName, err)
	}

	taskMgrCheckInterval, err := cmdutil.GetDuration(cmd, taskMgrCheckIntervalFlagName,
		taskMgrCheckIntervalEnvKey, defaultTaskMgrCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", taskMgrCheckIntervalFlagName, err)
	}

	vctParams, err := getVCTParams(cmd)
	if err != nil {
		return nil, err
	}

	anchorStatusMonitoringInterval, err := cmdutil.GetDuration(cmd, anchorStatusMonitoringIntervalFlagName,
		anchorStatusMonitoringIntervalEnvKey, defaultAnchorStatusMonitoringInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", anchorStatusMonitoringIntervalFlagName, err)
	}

	anchorStatusInProcessGracePeriod, err := cmdutil.GetDuration(cmd, anchorStatusInProcessGracePeriodFlagName,
		anchorStatusInProcessGracePeriodEnvKey, defaultAnchorStatusInProcessGracePeriod)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", anchorStatusInProcessGracePeriodFlagName, err)
	}

	witnessPolicyCacheExpiration, err := cmdutil.GetDuration(cmd, witnessPolicyCacheExpirationFlagName,
		witnessPolicyCacheExpirationEnvKey, defaultWitnessPolicyCacheExpiration)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", witnessPolicyCacheExpirationFlagName, err)
	}

	requestTokens := getRequestTokens(cmd)

	apServiceParams, err := newAPServiceParams(serviceID, httpParams.externalEndpoint, kmsParams, enableDevMode)
	if err != nil {
		return nil, err
	}

	anchorCredentialParams := getAnchorCredentialParameters(cmd, httpParams.externalEndpoint, apServiceParams.serviceIRI().String())

	return &orbParameters{
		http:                             httpParams,
		sidetree:                         sidetreeParams,
		discoveryDomain:                  discoveryDomain,
		apServiceParams:                  apServiceParams,
		allowedOrigins:                   allowedOrigins,
		allowedOriginsCacheExpiration:    allowedOriginsCacheExpiration,
		allowedDIDWebDomains:             allowedDIDWebDomains,
		cas:                              casParams,
		mqParams:                         mqParams,
		opQueueParams:                    opQueueParams,
		batchWriterTimeout:               batchWriterTimeout,
		anchorCredentialParams:           anchorCredentialParams,
		logLevel:                         loggingLevel,
		dbParameters:                     dbParams,
		discovery:                        discoveryParams,
		witnessProof:                     witnessProofParams,
		syncTimeout:                      syncTimeout,
		didDiscoveryEnabled:              didDiscoveryEnabled,
		unpublishedOperations:            unpublishedOperationsParams,
		resolveFromAnchorOrigin:          resolveFromAnchorOrigin,
		verifyLatestFromAnchorOrigin:     verifyLatestFromAnchorOrigin,
		auth:                             authParams,
		activityPub:                      activityPubParams,
		enableDevMode:                    enableDevMode,
		enableMaintenanceMode:            enableMaintenanceMode,
		enableVCT:                        enableVCT,
		nodeInfoRefreshInterval:          nodeInfoRefreshInterval,
		contextProviderURLs:              contextProviderURLs,
		dataExpiryCheckInterval:          dataExpiryCheckInterval,
		taskMgrCheckInterval:             taskMgrCheckInterval,
		vct:                              vctParams,
		anchorStatusMonitoringInterval:   anchorStatusMonitoringInterval,
		anchorStatusInProcessGracePeriod: anchorStatusInProcessGracePeriod,
		witnessPolicyCacheExpiration:     witnessPolicyCacheExpiration,
		dataURIMediaType:                 dataURIMediaType,
		kmsParams:                        kmsParams,
		requestTokens:                    requestTokens,
		observability:                    observabilityParams,
	}, nil
}

type httpParams struct {
	hostURL                 string
	externalEndpoint        string
	tls                     *tlsParameters
	timeout                 time.Duration
	dialTimeout             time.Duration
	serverIdleTimeout       time.Duration
	serverReadHeaderTimeout time.Duration
}

func getHTTPParams(cmd *cobra.Command) (*httpParams, error) {
	hostURL, err := cmdutil.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	externalEndpoint, err := cmdutil.GetUserSetVarFromString(cmd, externalEndpointFlagName, externalEndpointEnvKey, true)
	if err != nil {
		return nil, err
	}

	if externalEndpoint == "" {
		externalEndpoint = hostURL
	}

	tlsParams, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	httpDialTimeout, err := cmdutil.GetDuration(cmd, httpDialTimeoutFlagName, httpDialTimeoutEnvKey, defaultHTTPDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpDialTimeoutFlagName, err)
	}

	serverIdleTimeout, err := cmdutil.GetDuration(cmd, serverIdleTimeoutFlagName, serverIdleTimeoutEnvKey, defaultServerIdleTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", serverIdleTimeoutFlagName, err)
	}

	serverReadHeaderTimeout, err := cmdutil.GetDuration(cmd, serverReadHeaderTimeoutFlagName, serverReadHeaderTimeoutEnvKey,
		defaultServerReadHeaderTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", serverReadHeaderTimeoutFlagName, err)
	}

	httpTimeout, err := cmdutil.GetDuration(cmd, httpTimeoutFlagName, httpTimeoutEnvKey, defaultHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpTimeoutFlagName, err)
	}

	return &httpParams{
		hostURL:                 hostURL,
		externalEndpoint:        externalEndpoint,
		tls:                     tlsParams,
		timeout:                 httpTimeout,
		dialTimeout:             httpDialTimeout,
		serverIdleTimeout:       serverIdleTimeout,
		serverReadHeaderTimeout: serverReadHeaderTimeout,
	}, nil
}

type sidetreeParams struct {
	didNamespace           string
	didAliases             []string
	protocolVersions       []string
	currentProtocolVersion string
}

func getSidetreeParams(cmd *cobra.Command) (*sidetreeParams, error) {
	didNamespace, err := cmdutil.GetUserSetVarFromString(cmd, didNamespaceFlagName, didNamespaceEnvKey, false)
	if err != nil {
		return nil, err
	}

	didAliases := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, didAliasesFlagName, didAliasesEnvKey)

	protocolVersionsArr := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, sidetreeProtocolVersionsFlagName,
		sidetreeProtocolVersionsEnvKey)

	defaultProtocolVersions := []string{"1.0"}

	protocolVersions := defaultProtocolVersions

	if len(protocolVersionsArr) > 0 {
		protocolVersions = protocolVersionsArr
	}

	currentProtocolVersion := cmdutil.GetUserSetOptionalVarFromString(cmd, currentSidetreeProtocolVersionFlagName,
		currentSidetreeProtocolVersionEnvKey)

	return &sidetreeParams{
		didNamespace:           didNamespace,
		didAliases:             didAliases,
		protocolVersions:       protocolVersions,
		currentProtocolVersion: currentProtocolVersion,
	}, nil
}

type casParams struct {
	casType                        string
	ipfsURL                        string
	localCASReplicateInIPFSEnabled bool
	cidVersion                     int
	ipfsTimeout                    time.Duration
}

func getCASParams(cmd *cobra.Command) (*casParams, error) {
	casType, err := cmdutil.GetUserSetVarFromString(cmd, casTypeFlagName, casTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	ipfsURL, err := cmdutil.GetUserSetVarFromString(cmd, ipfsURLFlagName, ipfsURLEnvKey, true)
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

	ipfsTimeout, err := cmdutil.GetDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ipfsTimeoutFlagName, err)
	}

	localCASReplicateInIPFSEnabled, err := cmdutil.GetBool(cmd, localCASReplicateInIPFSFlagName, localCASReplicateInIPFSEnvKey,
		defaultLocalCASReplicateInIPFSEnabled)
	if err != nil {
		return nil, err
	}

	cidVersionString, err := cmdutil.GetUserSetVarFromString(cmd, cidVersionFlagName, cidVersionEnvKey, true)
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

	return &casParams{
		casType:                        casType,
		ipfsURL:                        ipfsURL,
		ipfsTimeout:                    ipfsTimeout,
		localCASReplicateInIPFSEnabled: localCASReplicateInIPFSEnabled,
		cidVersion:                     cidVersion,
	}, nil
}

type witnessProofParams struct {
	maxWitnessDelay             time.Duration
	maxClockSkew                time.Duration
	witnessStoreExpiryPeriod    time.Duration
	proofMonitoringExpiryPeriod time.Duration
	signWithLocalWitness        bool
}

func getWitnessProofParams(cmd *cobra.Command) (*witnessProofParams, error) {
	maxWitnessDelay, err := cmdutil.GetDuration(cmd, maxWitnessDelayFlagName, maxWitnessDelayEnvKey, defaultMaxWitnessDelay)
	if err != nil {
		return nil, err
	}

	maxClockSkew, err := cmdutil.GetDuration(cmd, maxClockSkewFlagName, maxClockSkewEnvKey, defaultMaxClockSkew)
	if err != nil {
		return nil, err
	}

	witnessStoreExpiryPeriod, err := cmdutil.GetDuration(cmd, witnessStoreExpiryPeriodFlagName, witnessStoreExpiryPeriodEnvKey,
		defaultWitnessStoreExpiryDelta)
	if err != nil {
		return nil, err
	}

	if witnessStoreExpiryPeriod <= maxWitnessDelay+maxClockSkew {
		return nil, fmt.Errorf("witness store expiry period must me greater than maximum witness delay + max clock skew")
	}

	// default behavior is to always sign with local witness
	signWithLocalWitness, err := cmdutil.GetBool(cmd, signWithLocalWitnessFlagName, signWithLocalWitnessEnvKey, true)
	if err != nil {
		return nil, err
	}

	proofMonitoringExpiryPeriod, err := cmdutil.GetDuration(cmd, vctProofMonitoringExpiryPeriodFlagName,
		vctProofMonitoringExpiryPeriodEnvKey, defaultProofMonitoringExpiryPeriod)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", vctProofMonitoringExpiryPeriodFlagName, err)
	}

	return &witnessProofParams{
		maxWitnessDelay:             maxWitnessDelay,
		maxClockSkew:                maxClockSkew,
		witnessStoreExpiryPeriod:    witnessStoreExpiryPeriod,
		proofMonitoringExpiryPeriod: proofMonitoringExpiryPeriod,
		signWithLocalWitness:        signWithLocalWitness,
	}, nil
}

type unpublishedOperationsStoreParams struct {
	enabled            bool
	operationTypes     []operation.Type
	includeUnpublished bool
	includePublished   bool
	lifespan           time.Duration
}

func getUnpublishedOperationsParams(cmd *cobra.Command) (*unpublishedOperationsStoreParams, error) {
	unpublishedOperationStoreEnabled, err := cmdutil.GetBool(cmd, enableUnpublishedOperationStoreFlagName,
		enableUnpublishedOperationStoreEnvKey, defaultUnpublishedOperationStoreEnabled)
	if err != nil {
		return nil, err
	}

	unpublishedOperationStoreOperationTypesArr := cmdutil.GetUserSetOptionalVarFromArrayString(cmd,
		unpublishedOperationStoreOperationTypesFlagName, unpublishedOperationStoreOperationTypesEnvKey)

	defaultOperationTypes := []operation.Type{operation.TypeCreate, operation.TypeUpdate}

	unpublishedOperationStoreOperationTypes := defaultOperationTypes

	if len(unpublishedOperationStoreOperationTypesArr) > 0 {
		var configuredOpTypes []operation.Type

		for _, t := range unpublishedOperationStoreOperationTypesArr {
			configuredOpTypes = append(configuredOpTypes, operation.Type(t))
		}

		unpublishedOperationStoreOperationTypes = configuredOpTypes
	}

	includeUnpublishedOperations, err := cmdutil.GetBool(cmd, includeUnpublishedOperationsFlagName, includeUnpublishedOperationsEnvKey,
		defaultIncludeUnpublishedOperations)
	if err != nil {
		return nil, err
	}

	includePublishedOperations, err := cmdutil.GetBool(cmd, includePublishedOperationsFlagName, includePublishedOperationsEnvKey,
		defaultIncludePublishedOperations)
	if err != nil {
		return nil, err
	}

	unpublishedOperationLifespan, err := cmdutil.GetDuration(cmd, unpublishedOperationLifespanFlagName,
		unpublishedOperationLifespanEnvKey, defaultUnpublishedOperationLifespan)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", unpublishedOperationLifespanFlagName, err)
	}

	return &unpublishedOperationsStoreParams{
		enabled:            unpublishedOperationStoreEnabled,
		operationTypes:     unpublishedOperationStoreOperationTypes,
		includeUnpublished: includeUnpublishedOperations,
		includePublished:   includePublishedOperations,
		lifespan:           unpublishedOperationLifespan,
	}, nil
}

type discoveryParams struct {
	domains          []string
	minimumResolvers int
}

func getDiscoveryParams(cmd *cobra.Command) (*discoveryParams, error) {
	domains := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, discoveryDomainsFlagName, discoveryDomainsEnvKey)

	minimumResolvers, err := cmdutil.GetInt(cmd, discoveryMinimumResolversFlagName, discoveryMinimumResolversEnvKey,
		defaultDiscoveryMinimumResolvers)
	if err != nil {
		return nil, err
	}

	return &discoveryParams{
		domains:          domains,
		minimumResolvers: minimumResolvers,
	}, nil
}

type authParams struct {
	httpSignaturesEnabled  bool
	tokenDefinitions       []*auth.TokenDef
	tokens                 map[string]string
	clientTokenDefinitions []*auth.TokenDef
	clientTokens           map[string]string
	inviteWitnessPolicy    acceptRejectPolicy
	followPolicy           acceptRejectPolicy
}

func getAuthParams(cmd *cobra.Command) (*authParams, error) {
	httpSignaturesEnabled, err := cmdutil.GetBool(cmd, httpSignaturesEnabledFlagName, httpSignaturesEnabledEnvKey,
		defaulthttpSignaturesEnabled)
	if err != nil {
		return nil, err
	}

	authTokenDefs, err := getAuthTokenDefinitions(cmd, authTokensDefFlagName, authTokensDefEnvKey, nil)
	if err != nil {
		return nil, fmt.Errorf("authorization token definitions: %w", err)
	}

	authTokens, err := getAuthTokens(cmd, authTokensFlagName, authTokensEnvKey, nil)
	if err != nil {
		return nil, fmt.Errorf("authorization tokens: %w", err)
	}

	clientAuthTokenDefs, err := getAuthTokenDefinitions(cmd, clientAuthTokensDefFlagName, clientAuthTokensDefEnvKey, authTokenDefs)
	if err != nil {
		return nil, fmt.Errorf("client authorization token definitions: %w", err)
	}

	clientAuthTokens, err := getAuthTokens(cmd, clientAuthTokensFlagName, clientAuthTokensEnvKey, authTokens)
	if err != nil {
		return nil, fmt.Errorf("client authorization tokens: %w", err)
	}

	followAuthPolicy, err := getFollowAuthPolicy(cmd)
	if err != nil {
		return nil, err
	}

	inviteWitnessAuthPolicy, err := getInviteWitnessAuthPolicy(cmd)
	if err != nil {
		return nil, err
	}

	return &authParams{
		httpSignaturesEnabled:  httpSignaturesEnabled,
		tokenDefinitions:       authTokenDefs,
		tokens:                 authTokens,
		clientTokenDefinitions: clientAuthTokenDefs,
		clientTokens:           clientAuthTokens,
		followPolicy:           followAuthPolicy,
		inviteWitnessPolicy:    inviteWitnessAuthPolicy,
	}, nil
}

type vctParams struct {
	proofMonitoringInterval      time.Duration
	logMonitoringInterval        time.Duration
	logMonitoringTreeSize        uint64
	logMonitoringGetEntriesRange int
	logEntriesStoreEnabled       bool
}

func getVCTParams(cmd *cobra.Command) (*vctParams, error) {
	vctProofMonitoringInterval, err := cmdutil.GetDuration(cmd, vctProofMonitoringIntervalFlagName, vctProofMonitoringIntervalEnvKey,
		defaultVCTProofMonitoringInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", vctProofMonitoringIntervalFlagName, err)
	}

	vctLogMonitoringInterval, err := cmdutil.GetDuration(cmd, vctLogMonitoringIntervalFlagName, vctLogMonitoringIntervalEnvKey,
		defaultVCTLogMonitoringInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", vctLogMonitoringIntervalFlagName, err)
	}

	vctLogMonitoringMaxTreeSizeStr := cmdutil.GetUserSetOptionalVarFromString(cmd, vctLogMonitoringMaxTreeSizeFlagName,
		vctLogMonitoringMaxTreeSizeEnvKey)

	vctLogMonitoringMaxTreeSize := uint64(defaultVCTLogMonitoringMaxTreeSize)
	if vctLogMonitoringMaxTreeSizeStr != "" {
		vctLogMonitoringMaxTreeSize, err = strconv.ParseUint(vctLogMonitoringMaxTreeSizeStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vctLogMonitoringMaxTreeSizeFlagName, err)
		}
	}

	vctLogMonitoringGetEntriesRangeStr := cmdutil.GetUserSetOptionalVarFromString(cmd, vctLogMonitoringGetEntriesRangeFlagName,
		vctLogMonitoringGetEntriesRangeEnvKey)

	vctLogMonitoringGetEntriesRange := defaultVCTLogMonitoringGetEntriesRange
	if vctLogMonitoringGetEntriesRangeStr != "" {
		getEntriesRange, e := strconv.ParseUint(vctLogMonitoringGetEntriesRangeStr, 10, 64)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", vctLogMonitoringGetEntriesRangeFlagName, e)
		}

		vctLogMonitoringGetEntriesRange = int(getEntriesRange)
	}

	vctLogEntriesStoreEnabled, err := cmdutil.GetBool(cmd, vctLogEntriesStoreEnabledFlagName, vctLogEntriesStoreEnabledEnvKey,
		defaultVCTLogEntriesStoreEnabled)
	if err != nil {
		return nil, err
	}

	return &vctParams{
		proofMonitoringInterval:      vctProofMonitoringInterval,
		logMonitoringInterval:        vctLogMonitoringInterval,
		logMonitoringTreeSize:        vctLogMonitoringMaxTreeSize,
		logMonitoringGetEntriesRange: vctLogMonitoringGetEntriesRange,
		logEntriesStoreEnabled:       vctLogEntriesStoreEnabled,
	}, nil
}

type activityPubParams struct {
	pageSize                    int
	anchorSyncPeriod            time.Duration
	anchorSyncAcceleratedPeriod time.Duration
	anchorSyncMinActivityAge    time.Duration
	anchorSyncMaxActivities     int
	clientCacheSize             int
	clientCacheExpiration       time.Duration
	iriCacheSize                int
	iriCacheExpiration          time.Duration
}

func getActivityPubParams(cmd *cobra.Command) (*activityPubParams, error) {
	activityPubPageSize, err := getActivityPubPageSize(cmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", activityPubPageSizeFlagName, err)
	}

	syncPeriod, acceleratedSyncPeriod, minActivityAge, maxActivities, err := getAnchorSyncParameters(cmd)
	if err != nil {
		return nil, err
	}

	apClientCacheSize, apClientCacheExpiration, err := getActivityPubClientParameters(cmd)
	if err != nil {
		return nil, err
	}

	apIRICacheSize, apIRICacheExpiration, err := getActivityPubIRICacheParameters(cmd)
	if err != nil {
		return nil, err
	}

	return &activityPubParams{
		pageSize:                    activityPubPageSize,
		anchorSyncPeriod:            syncPeriod,
		anchorSyncAcceleratedPeriod: acceleratedSyncPeriod,
		anchorSyncMinActivityAge:    minActivityAge,
		anchorSyncMaxActivities:     maxActivities,
		clientCacheSize:             apClientCacheSize,
		clientCacheExpiration:       apClientCacheExpiration,
		iriCacheSize:                apIRICacheSize,
		iriCacheExpiration:          apIRICacheExpiration,
	}, nil
}

func getActivityPubClientParameters(cmd *cobra.Command) (int, time.Duration, error) {
	return getActivityPubCacheParameters(cmd, &cacheParams{
		sizeFlag:          activityPubClientCacheSizeFlagName,
		sizeEnvKey:        activityPubClientCacheSizeEnvKey,
		defaultSize:       defaultActivityPubClientCacheSize,
		expirationFlag:    activityPubClientCacheExpirationFlagName,
		expirationEnvKey:  activityPubClientCacheExpirationEnvKey,
		defaultExpiration: defaultActivityPubClientCacheExpiration,
	})
}

func getActivityPubIRICacheParameters(cmd *cobra.Command) (int, time.Duration, error) {
	return getActivityPubCacheParameters(cmd, &cacheParams{
		sizeFlag:          activityPubIRICacheSizeFlagName,
		sizeEnvKey:        activityPubIRICacheSizeEnvKey,
		defaultSize:       defaultActivityPubIRICacheSize,
		expirationFlag:    activityPubIRICacheExpirationFlagName,
		expirationEnvKey:  activityPubIRICacheExpirationEnvKey,
		defaultExpiration: defaultActivityPubIRICacheExpiration,
	})
}

func getAllowedDIDWebDomains(cmd *cobra.Command) ([]*url.URL, error) {
	allowedDIDWebDomainsArray, err := cmdutil.GetUserSetVarFromArrayString(cmd, allowedDIDWebDomainsFlagName,
		allowedDIDWebDomainsEnvKey, true)
	if err != nil {
		return nil, err
	}

	var allowedDIDWebDomains []*url.URL

	for _, domain := range allowedDIDWebDomainsArray {
		domainURL, e := url.Parse(domain)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", allowedDIDWebDomainsFlagName, e)
		}

		allowedDIDWebDomains = append(allowedDIDWebDomains, domainURL)
	}

	return allowedDIDWebDomains, nil
}

func getObservabilityParams(cmd *cobra.Command) (*observabilityParams, error) {
	metricsProviderName, err := getMetricsProviderName(cmd)
	if err != nil {
		return nil, err
	}

	var metricsURL string

	if metricsProviderName == "prometheus" {
		metricsURL, err = cmdutil.GetUserSetVarFromString(cmd, promHTTPURLFlagName, promHTTPURLEnvKey, false)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	tracingParams, err := getTracingParams(cmd)
	if err != nil {
		return nil, err
	}

	return &observabilityParams{
		metrics: metricsParams{
			providerName: metricsProviderName,
			url:          metricsURL,
		},
		tracing: *tracingParams,
	}, nil
}

func getMetricsProviderName(cmd *cobra.Command) (string, error) {
	metricsProvider, err := cmdutil.GetUserSetVarFromString(cmd, metricsProviderFlagName, metricsProviderEnvKey, true)
	if err != nil {
		return "", err
	}

	return metricsProvider, nil
}

func getTracingParams(cmd *cobra.Command) (*tracingParams, error) {
	serviceName := cmdutil.GetUserSetOptionalVarFromString(cmd, tracingServiceNameFlagName, tracingServiceNameEnvKey)
	if serviceName == "" {
		serviceName = defaultTracingServiceName
	}

	params := &tracingParams{
		provider:    cmdutil.GetUserSetOptionalVarFromString(cmd, tracingProviderFlagName, tracingProviderEnvKey),
		serviceName: serviceName,
	}

	switch params.provider {
	case tracing.ProviderNone:
		return params, nil
	case tracing.ProviderJaeger:
		var err error

		params.collectorURL, err = cmdutil.GetUserSetVarFromString(cmd, tracingCollectorURLFlagName,
			tracingCollectorURLEnvKey, false)
		if err != nil {
			return nil, err
		}

		params.enabled = true
	default:
		return nil, fmt.Errorf("unsupported tracing provider: %s", params.provider)
	}

	return params, nil
}

func getRequestTokens(cmd *cobra.Command) map[string]string {
	requestTokens := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, requestTokensFlagName,
		requestTokensEnvKey)

	tokens := make(map[string]string)

	for _, token := range requestTokens {
		split := strings.Split(token, "=")
		switch len(split) {
		case splitRequestTokenLength:
			tokens[split[0]] = split[1]
		default:
			logger.Warn("Invalid token", logfields.WithAuthToken(token))
		}
	}

	return tokens
}

func getAnchorCredentialParameters(cmd *cobra.Command, externalEndpoint, serviceIRI string) *anchorCredentialParams {
	domain := cmdutil.GetUserSetOptionalVarFromString(cmd, anchorCredentialDomainFlagName, anchorCredentialDomainEnvKey)
	if domain == "" {
		domain = externalEndpoint
	}

	return &anchorCredentialParams{
		issuer: serviceIRI,
		url:    fmt.Sprintf("%s/vc", externalEndpoint),
		domain: domain,
	}
}

func getDBParameters(cmd *cobra.Command) (*dbParameters, error) {
	databaseType, err := cmdutil.GetUserSetVarFromString(cmd, databaseTypeFlagName,
		databaseTypeEnvKey, false)
	if err != nil {
		return nil, err
	}

	databaseURL, err := cmdutil.GetUserSetVarFromString(cmd, databaseURLFlagName,
		databaseURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	databasePrefix, err := cmdutil.GetUserSetVarFromString(cmd, databasePrefixFlagName,
		databasePrefixEnvKey, true)
	if err != nil {
		return nil, err
	}

	databaseTimeout, err := cmdutil.GetDuration(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey, defaultDatabaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", databaseTimeoutFlagName, err)
	}

	return &dbParameters{
		databaseType:    databaseType,
		databaseURL:     databaseURL,
		databasePrefix:  databasePrefix,
		databaseTimeout: databaseTimeout,
	}, nil
}

func getAuthTokenDefinitions(cmd *cobra.Command, flagName, envKey string, defaultDefs []*auth.TokenDef) ([]*auth.TokenDef, error) {
	authTokenDefsStr, err := cmdutil.GetUserSetVarFromArrayString(cmd, flagName, envKey, true)
	if err != nil {
		return nil, err
	}

	if len(authTokenDefsStr) == 0 {
		return defaultDefs, nil
	}

	logger.Debug("Auth tokens definition", logfields.WithAuthTokens(authTokenDefsStr...))

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

		logger.Debug("Adding write token definition for endpoint",
			logfields.WithServiceEndpoint(def.EndpointExpression), logfields.WithAuthTokens(def.WriteTokens...))

		logger.Debug("Adding read token definition for endpoint",
			logfields.WithServiceEndpoint(def.EndpointExpression), logfields.WithAuthTokens(def.ReadTokens...))

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

func getPrivateKeys(cmd *cobra.Command, flagName, envKey string) (map[string]string, error) {
	privateKeyStr := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, flagName, envKey)

	if len(privateKeyStr) == 0 {
		return nil, nil //nolint:nilnil
	}

	privateKeys := make(map[string]string)

	for _, keyValStr := range privateKeyStr {
		keyVal := strings.Split(keyValStr, "=")

		if len(keyVal) != 2 {
			return nil, fmt.Errorf("invalid private key string [%s]", keyValStr)
		}

		privateKeys[keyVal[0]] = keyVal[1]
	}

	return privateKeys, nil
}

func getAuthTokens(cmd *cobra.Command, flagName, envKey string, defaultTokens map[string]string) (map[string]string, error) {
	authTokensStr, err := cmdutil.GetUserSetVarFromArrayString(cmd, flagName, envKey, true)
	if err != nil {
		return nil, err
	}

	if len(authTokensStr) == 0 {
		return defaultTokens, nil
	}

	authTokens := make(map[string]string)

	for _, keyValStr := range authTokensStr {
		keyVal := strings.Split(keyValStr, "=")

		if len(keyVal) != 2 {
			return nil, fmt.Errorf("invalid auth token string [%s]: %w", authTokensStr, err)
		}

		logger.Debug("Adding token", logfields.WithKey(keyVal[0]), logfields.WithValue(keyVal[1]))

		authTokens[keyVal[0]] = keyVal[1]
	}

	return authTokens, nil
}

func getActivityPubPageSize(cmd *cobra.Command) (int, error) {
	activityPubPageSizeStr, err := cmdutil.GetUserSetVarFromString(cmd, activityPubPageSizeFlagName,
		activityPubPageSizeEnvKey, true)
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

type mqParams struct {
	endpoint                  string
	observerPoolSize          int
	outboxPoolSize            int
	inboxPoolSize             int
	opQueuePoolSize           int
	anchorLinksetPoolSize     int
	maxConnectionChannels     int
	publisherChannelPoolSize  int
	publisherConfirmDelivery  bool
	maxConnectRetries         int
	maxRedeliveryAttempts     int
	redeliveryMultiplier      float64
	redeliveryInitialInterval time.Duration
	maxRedeliveryInterval     time.Duration
}

func getMQParameters(cmd *cobra.Command) (*mqParams, error) {
	mqURL, err := cmdutil.GetUserSetVarFromString(cmd, mqURLFlagName, mqURLEnvKey, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mqURLFlagName, err)
	}

	mqObserverPoolSize, err := cmdutil.GetInt(cmd, mqObserverPoolFlagName, mqObserverPoolEnvKey, mqDefaultObserverPoolSize)
	if err != nil {
		return nil, err
	}

	mqOutboxPoolSize, err := cmdutil.GetInt(cmd, mqOutboxPoolFlagName, mqOutboxPoolEnvKey, mqDefaultOutboxPoolSize)
	if err != nil {
		return nil, err
	}

	mqInboxPoolSize, err := cmdutil.GetInt(cmd, mqInboxPoolFlagName, mqInboxPoolEnvKey, mqDefaultInboxPoolSize)
	if err != nil {
		return nil, err
	}

	mqOpQueuePoolSize, err := cmdutil.GetInt(cmd, mqOPQueuePoolFlagName, mqOPQueuePoolEnvKey, mqDefaultOpQueuePoolSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mqOPQueuePoolFlagName, err)
	}

	mqAnchorLinksetPoolSize, err := cmdutil.GetInt(cmd, mqAnchorLinksetPoolFlagName, mqAnchorLinksetPoolEnvKey, mqDefaultAnchorLinksetPoolSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mqAnchorLinksetPoolFlagName, err)
	}

	mqMaxConnectionChannels, err := cmdutil.GetInt(cmd, mqMaxConnectionChannelsFlagName,
		mqMaxConnectionChannelsEnvKey, mqDefaultMaxConnectionSubscriptions)
	if err != nil {
		return nil, err
	}

	mqPublisherChannelPoolSize, err := cmdutil.GetInt(cmd, mqPublisherChannelPoolSizeFlagName,
		mqPublisherChannelPoolSizeEnvKey, mqDefaultPublisherChannelPoolSize)
	if err != nil {
		return nil, err
	}

	mqPublisherConfirmDelivery, err := cmdutil.GetBool(cmd, mqPublisherConfirmDeliveryFlagName,
		mqPublisherConfirmDeliveryEnvKey, mqDefaultPublisherConfirmDelivery)
	if err != nil {
		return nil, err
	}

	mqMaxConnectRetries, err := cmdutil.GetInt(cmd, mqConnectMaxRetriesFlagName, mqConnectMaxRetriesEnvKey,
		mqDefaultConnectMaxRetries)
	if err != nil {
		return nil, err
	}

	mqMaxRedeliveryAttempts, err := cmdutil.GetInt(cmd, mqRedeliveryMaxAttemptsFlagName, mqRedeliveryMaxAttemptsEnvKey,
		mqDefaultRedeliveryMaxAttempts)
	if err != nil {
		return nil, err
	}

	mqRedeliveryMultiplier, err := cmdutil.GetFloat(cmd, mqRedeliveryMultiplierFlagName, mqRedeliveryMultiplierEnvKey,
		mqDefaultRedeliveryMultiplier)
	if err != nil {
		return nil, err
	}

	mqRedeliveryInitialInterval, err := cmdutil.GetDuration(cmd, mqRedeliveryInitialIntervalFlagName,
		mqRedeliveryInitialIntervalEnvKey, mqDefaultRedeliveryInitialInterval)
	if err != nil {
		return nil, err
	}

	mqRedeliveryMaxInterval, err := cmdutil.GetDuration(cmd, mqRedeliveryMaxIntervalFlagName,
		mqRedeliveryMaxIntervalEnvKey, mqDefaultRedeliveryMaxInterval)
	if err != nil {
		return nil, err
	}

	return &mqParams{
		endpoint:                  mqURL,
		observerPoolSize:          mqObserverPoolSize,
		outboxPoolSize:            mqOutboxPoolSize,
		inboxPoolSize:             mqInboxPoolSize,
		anchorLinksetPoolSize:     mqAnchorLinksetPoolSize,
		maxConnectionChannels:     mqMaxConnectionChannels,
		publisherChannelPoolSize:  mqPublisherChannelPoolSize,
		publisherConfirmDelivery:  mqPublisherConfirmDelivery,
		maxConnectRetries:         mqMaxConnectRetries,
		maxRedeliveryAttempts:     mqMaxRedeliveryAttempts,
		redeliveryMultiplier:      mqRedeliveryMultiplier,
		redeliveryInitialInterval: mqRedeliveryInitialInterval,
		maxRedeliveryInterval:     mqRedeliveryMaxInterval,
		opQueuePoolSize:           mqOpQueuePoolSize,
	}, nil
}

func getOpQueueParameters(cmd *cobra.Command, mqParams *mqParams) (*opqueue.Config, error) {
	taskMonitorInterval, err := cmdutil.GetDuration(cmd, opQueueTaskMonitorIntervalFlagName,
		opQueueTaskMonitorIntervalEnvKey, opQueueDefaultTaskMonitorInterval)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opQueueTaskMonitorIntervalFlagName, err)
	}

	taskExpiration, err := cmdutil.GetDuration(cmd, opQueueTaskExpirationFlagName,
		opQueueTaskExpirationEnvKey, opQueueDefaultTaskExpiration)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opQueueTaskExpirationFlagName, err)
	}

	maxOperationsToRepost, err := cmdutil.GetInt(cmd, opQueueMaxOperationsToRepostFlagName, opQueueMaxOperationsToRepostEnvKey,
		opQueueDefaultMaxOperationsToRepost)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opQueueMaxOperationsToRepostFlagName, err)
	}

	operationLifespan, err := cmdutil.GetDuration(cmd, opQueueOperationLifespanFlagName, opQueueOperationLifespanEnvKey,
		opQueueDefaultOperationLifespan)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opQueueOperationLifespanFlagName, err)
	}

	return &opqueue.Config{
		TaskMonitorInterval:   taskMonitorInterval,
		TaskExpiration:        taskExpiration,
		MaxOperationsToRepost: maxOperationsToRepost,
		OperationLifeSpan:     operationLifespan,
		PoolSize:              mqParams.opQueuePoolSize,
		MaxRetries:            mqParams.maxRedeliveryAttempts,
		RetriesInitialDelay:   mqParams.redeliveryInitialInterval,
		RetriesMaxDelay:       mqParams.maxRedeliveryInterval,
		RetriesMultiplier:     mqParams.redeliveryMultiplier,
	}, nil
}

func getTLS(cmd *cobra.Command) (*tlsParameters, error) {
	tlsSystemCertPool, err := cmdutil.GetBool(cmd, tlsSystemCertPoolFlagName, tlsSystemCertPoolEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsCACerts := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	tlsServeCertPath := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsCertificateFlagName, tlsCertificateLEnvKey)

	tlsServeKeyPath := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsKeyFlagName, tlsKeyEnvKey)

	return &tlsParameters{
		systemCertPool: tlsSystemCertPool,
		caCerts:        tlsCACerts,
		serveCertPath:  tlsServeCertPath,
		serveKeyPath:   tlsServeKeyPath,
	}, nil
}

func getFollowAuthPolicy(cmd *cobra.Command) (acceptRejectPolicy, error) {
	authType, err := cmdutil.GetUserSetVarFromString(cmd, followAuthPolicyFlagName, followAuthPolicyEnvKey, true)
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
	authType, err := cmdutil.GetUserSetVarFromString(cmd, inviteWitnessAuthPolicyFlagName, inviteWitnessAuthPolicyEnvKey, true)
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

type cacheParams struct {
	sizeFlag    string
	sizeEnvKey  string
	defaultSize int

	expirationFlag    string
	expirationEnvKey  string
	defaultExpiration time.Duration
}

func getActivityPubCacheParameters(cmd *cobra.Command, params *cacheParams) (int, time.Duration, error) {
	cacheSize := params.defaultSize

	cacheSizeStr, err := cmdutil.GetUserSetVarFromString(cmd, params.sizeFlag, params.sizeEnvKey, true)
	if err != nil {
		return 0, 0, err
	}

	if cacheSizeStr != "" {
		cacheSize, err = strconv.Atoi(cacheSizeStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid value [%s] for parameter [%s]: %w", cacheSizeStr, params.sizeFlag, err)
		}

		if cacheSize <= 0 {
			return 0, 0, fmt.Errorf("value for parameter [%s] must be grater than 0", params.sizeFlag)
		}
	}

	cacheExpiration, err := cmdutil.GetDuration(cmd, params.expirationFlag, params.expirationEnvKey, params.defaultExpiration)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid value for parameter [%s]: %w", params.expirationFlag, err)
	}

	return cacheSize, cacheExpiration, nil
}

func getAnchorSyncParameters(cmd *cobra.Command) (syncPeriod, acceleratedSyncPeriod,
	minActivityAge time.Duration, maxActivities int, err error,
) {
	syncPeriod, err = cmdutil.GetDuration(cmd, anchorSyncIntervalFlagName, anchorSyncIntervalEnvKey, defaultAnchorSyncInterval)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("%s: %w", anchorSyncIntervalFlagName, err)
	}

	acceleratedSyncPeriod, err = cmdutil.GetDuration(cmd, anchorSyncAcceleratedIntervalFlagName, anchorSyncAcceleratedIntervalEnvKey,
		defaultAnchorSyncAcceleratedInterval)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("%s: %w", anchorSyncIntervalFlagName, err)
	}

	minActivityAge, err = cmdutil.GetDuration(cmd, anchorSyncMinActivityAgeFlagName, anchorSyncMinActivityAgeEnvKey,
		defaultAnchorSyncMinActivityAge)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("%s: %w", anchorSyncMinActivityAgeFlagName, err)
	}

	maxActivities, err = cmdutil.GetInt(cmd, anchorSyncMaxActivitiesFlagName, anchorSyncMaxActivitiesEnvKey,
		defaultAnchorSyncMaxActivities)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("%s: %w", anchorSyncMinActivityAgeFlagName, err)
	}

	return syncPeriod, acceleratedSyncPeriod, minActivityAge, maxActivities, nil
}

func newAPServiceParams(apServiceID, externalEndpoint string,
	kmsParams *kmsParameters, enableDevMode bool,
) (params *apServiceParams, err error) {
	if apServiceID == "" {
		apServiceID = externalEndpoint + activityPubServicesPath
	}

	var apServiceEndpoint string

	if util.IsDID(apServiceID) {
		var e error

		apServiceEndpoint, e = getEndpointFromDIDWeb(apServiceID, enableDevMode)
		if e != nil {
			return nil, fmt.Errorf("get endpoint from DID [%s]: %w", apServiceID, e)
		}
	} else {
		apServiceEndpoint = apServiceID
	}

	serviceEndpoint, err := url.Parse(apServiceEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse ActivityPub service endpoint [%s]: %w",
			apServiceEndpoint, err)
	}

	u, err := url.Parse(externalEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse external endpoint [%s]: %w", externalEndpoint, err)
	}

	if serviceEndpoint.Scheme != u.Scheme {
		return nil,
			fmt.Errorf("external endpoint [%s] and service ID [%s] must have the same protocol scheme (e.g. https)",
				externalEndpoint, apServiceID)
	}

	if serviceEndpoint.Host != u.Host {
		return nil,
			fmt.Errorf("external endpoint [%s] and service ID [%s] must have the same host",
				externalEndpoint, apServiceID)
	}

	serviceIRI, err := url.Parse(apServiceID)
	if err != nil {
		return nil, fmt.Errorf("parse ActivityPub service IRI [%s]: %w",
			apServiceID, err)
	}

	return &apServiceParams{
		serviceEndpoint: func() *url.URL { return serviceEndpoint },
		serviceIRI:      func() *url.URL { return serviceIRI },
		publicKeyIRI: func() string {
			// Since kmsParams is mutable, we must process the IRI dynamically.
			if util.IsDID(apServiceID) {
				return fmt.Sprintf("%s#%s", apServiceID, kmsParams.httpSignActiveKeyID)
			}

			return fmt.Sprintf("%s/keys/%s", apServiceID, aphandler.MainKeyID)
		},
	}, nil
}

func getEndpointFromDIDWeb(id string, useHTTP bool) (string, error) {
	var protocolScheme string

	if useHTTP {
		protocolScheme = "http://"
	} else {
		protocolScheme = "https://"
	}

	parsedDID, err := did.Parse(id)
	if err != nil {
		return "", fmt.Errorf("parse did: %w", err)
	}

	if parsedDID.Method != "web" {
		return "", fmt.Errorf("unsupported DID method [%s]", "did:"+parsedDID.Method)
	}

	pathComponents := strings.Split(parsedDID.MethodSpecificID, ":")

	pathComponents[0], err = url.QueryUnescape(pathComponents[0])
	if err != nil {
		return "", fmt.Errorf("unescape did: %w", err)
	}

	return protocolScheme + strings.Join(pathComponents, "/"), nil
}

//nolint:funlen
func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().String(syncTimeoutFlagName, "1", syncTimeoutFlagUsage)
	startCmd.Flags().String(kmsEndpointFlagName, "", kmsEndpointFlagUsage)
	startCmd.Flags().StringP(vcSignActiveKeyIDFlagName, "", "", vcSignActiveKeyIDFlagUsage)
	startCmd.Flags().StringArrayP(vcSignPrivateKeysFlagName, "", []string{}, vcSignPrivateKeysFlagUsage)
	startCmd.Flags().String(httpSignActiveKeyIDFlagName, "", httpSignActiveKeyIDFlagUsage)
	startCmd.Flags().StringArrayP(httpSignPrivateKeyFlagName, "", []string{}, httpSignPrivateKeyFlagUsage)
	startCmd.Flags().String(secretLockKeyPathFlagName, "", secretLockKeyPathFlagUsage)
	startCmd.Flags().String(kmsTypeFlagName, "", kmsTypeFlagUsage)
	startCmd.Flags().StringP(externalEndpointFlagName, externalEndpointFlagShorthand, "", externalEndpointFlagUsage)
	startCmd.Flags().StringP(serviceIDFlagName, "", "", serviceIDFlagUsage)
	startCmd.Flags().String(discoveryDomainFlagName, "", discoveryDomainFlagUsage)
	startCmd.Flags().StringP(tlsCertificateFlagName, tlsCertificateFlagShorthand, "", tlsCertificateFlagUsage)
	startCmd.Flags().StringP(tlsKeyFlagName, tlsKeyFlagShorthand, "", tlsKeyFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(batchWriterTimeoutFlagName, batchWriterTimeoutFlagShorthand, "", batchWriterTimeoutFlagUsage)
	startCmd.Flags().StringP(maxWitnessDelayFlagName, maxWitnessDelayFlagShorthand, "", maxWitnessDelayFlagUsage)
	startCmd.Flags().StringP(maxClockSkewFlagName, "", "", maxClockSkewFlagUsage)
	startCmd.Flags().StringP(witnessStoreExpiryPeriodFlagName, "", "", witnessStoreExpiryPeriodFlagUsage)
	startCmd.Flags().StringP(signWithLocalWitnessFlagName, signWithLocalWitnessFlagShorthand, "", signWithLocalWitnessFlagUsage)
	startCmd.Flags().StringP(httpSignaturesEnabledFlagName, httpSignaturesEnabledShorthand, "", httpSignaturesEnabledUsage)
	startCmd.Flags().String(enableDidDiscoveryFlagName, "", enableDidDiscoveryUsage)
	startCmd.Flags().String(enableUnpublishedOperationStoreFlagName, "", enableUnpublishedOperationStoreUsage)
	startCmd.Flags().String(unpublishedOperationStoreOperationTypesFlagName, "", unpublishedOperationStoreOperationTypesUsage)
	startCmd.Flags().String(includeUnpublishedOperationsFlagName, "", includeUnpublishedOperationsUsage)
	startCmd.Flags().String(includePublishedOperationsFlagName, "", includePublishedOperationsUsage)
	startCmd.Flags().String(resolveFromAnchorOriginFlagName, "", resolveFromAnchorOriginUsage)
	startCmd.Flags().String(verifyLatestFromAnchorOriginFlagName, "", verifyLatestFromAnchorOriginUsage)
	startCmd.Flags().StringP(casTypeFlagName, casTypeFlagShorthand, "", casTypeFlagUsage)
	startCmd.Flags().StringP(ipfsURLFlagName, ipfsURLFlagShorthand, "", ipfsURLFlagUsage)
	startCmd.Flags().StringP(localCASReplicateInIPFSFlagName, "", "false", localCASReplicateInIPFSFlagUsage)
	startCmd.Flags().StringP(mqURLFlagName, mqURLFlagShorthand, "", mqURLFlagUsage)
	startCmd.Flags().StringP(mqObserverPoolFlagName, mqObserverPoolFlagShorthand, "", mqObserverPoolFlagUsage)
	startCmd.Flags().StringP(mqOutboxPoolFlagName, "", "", mqOutboxPoolFlagUsage)
	startCmd.Flags().StringP(mqInboxPoolFlagName, "", "", mqInboxPoolFlagUsage)
	startCmd.Flags().StringP(mqMaxConnectionChannelsFlagName, mqMaxConnectionChannelsFlagShorthand, "", mqMaxConnectionChannelsFlagUsage)
	startCmd.Flags().StringP(mqPublisherChannelPoolSizeFlagName, "", "", mqPublisherChannelPoolSizeFlagUsage)
	startCmd.Flags().StringP(mqPublisherConfirmDeliveryEnvKey, "", "", mqPublisherConfirmDeliveryFlagUsage)
	startCmd.Flags().StringP(mqConnectMaxRetriesFlagName, "", "", mqConnectMaxRetriesFlagUsage)
	startCmd.Flags().StringP(mqRedeliveryMaxAttemptsFlagName, "", "", mqRedeliveryMaxAttemptsFlagUsage)
	startCmd.Flags().StringP(mqRedeliveryInitialIntervalFlagName, "", "", mqRedeliveryInitialIntervalFlagUsage)
	startCmd.Flags().StringP(mqRedeliveryMultiplierFlagName, "", "", mqRedeliveryMultiplierFlagUsage)
	startCmd.Flags().StringP(mqRedeliveryMaxIntervalFlagName, "", "", mqRedeliveryMaxIntervalFlagUsage)
	startCmd.Flags().StringP(mqOPQueuePoolFlagName, mqOPQueuePoolFlagShorthand, "", mqOPQueuePoolFlagUsage)
	startCmd.Flags().StringP(mqAnchorLinksetPoolFlagName, "", "", mqAnchorLinksetPoolFlagUsage)
	startCmd.Flags().StringP(opQueueTaskMonitorIntervalFlagName, "", "", opQueueTaskMonitorIntervalFlagUsage)
	startCmd.Flags().StringP(opQueueTaskExpirationFlagName, "", "", opQueueTaskExpirationFlagUsage)
	startCmd.Flags().StringP(opQueueMaxOperationsToRepostFlagName, "", "", opQueueMaxOperationsToRepostFlagUsage)
	startCmd.Flags().StringP(opQueueOperationLifespanFlagName, "", "", opQueueOperationLifespanFlagUsage)
	startCmd.Flags().String(cidVersionFlagName, "1", cidVersionFlagUsage)
	startCmd.Flags().StringP(didNamespaceFlagName, didNamespaceFlagShorthand, "", didNamespaceFlagUsage)
	startCmd.Flags().StringArrayP(didAliasesFlagName, didAliasesFlagShorthand, []string{}, didAliasesFlagUsage)
	startCmd.Flags().StringArrayP(allowedOriginsFlagName, allowedOriginsFlagShorthand, []string{}, allowedOriginsFlagUsage)
	startCmd.Flags().StringArrayP(allowedDIDWebDomainsFlagName, "", []string{}, allowedDIDWebDomainsFlagUsage)
	startCmd.Flags().StringP(anchorCredentialDomainFlagName, anchorCredentialDomainFlagShorthand, "", anchorCredentialDomainFlagUsage)
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
	startCmd.Flags().StringP(discoveryMinimumResolversFlagName, "", "", discoveryMinimumResolversFlagUsage)
	startCmd.Flags().StringArrayP(authTokensDefFlagName, authTokensDefFlagShorthand, nil, authTokensDefFlagUsage)
	startCmd.Flags().StringArrayP(authTokensFlagName, authTokensFlagShorthand, nil, authTokensFlagUsage)
	startCmd.Flags().StringArrayP(clientAuthTokensDefFlagName, "", nil, clientAuthTokensDefFlagUsage)
	startCmd.Flags().StringArrayP(clientAuthTokensFlagName, "", nil, clientAuthTokensFlagUsage)
	startCmd.Flags().StringP(activityPubPageSizeFlagName, activityPubPageSizeFlagShorthand, "", activityPubPageSizeFlagUsage)
	startCmd.Flags().String(devModeEnabledFlagName, "false", devModeEnabledUsage)
	startCmd.Flags().String(maintenanceModeEnabledFlagName, "false", maintenanceModeEnabledUsage)
	startCmd.Flags().String(enableVCTFlagName, "false", enableVCTFlagUsage)
	startCmd.Flags().StringP(nodeInfoRefreshIntervalFlagName, nodeInfoRefreshIntervalFlagShorthand, "", nodeInfoRefreshIntervalFlagUsage)
	startCmd.Flags().StringP(ipfsTimeoutFlagName, ipfsTimeoutFlagShorthand, "", ipfsTimeoutFlagUsage)
	startCmd.Flags().StringArrayP(contextProviderFlagName, "", []string{}, contextProviderFlagUsage)
	startCmd.Flags().StringP(databaseTimeoutFlagName, "", "", databaseTimeoutFlagUsage)
	startCmd.Flags().StringP(unpublishedOperationLifespanFlagName, "", "", unpublishedOperationLifespanFlagUsage)
	startCmd.Flags().StringP(taskMgrCheckIntervalFlagName, "", "", taskMgrCheckIntervalFlagUsage)
	startCmd.Flags().StringP(dataExpiryCheckIntervalFlagName, "", "", dataExpiryCheckIntervalFlagUsage)
	startCmd.Flags().StringP(followAuthPolicyFlagName, followAuthPolicyFlagShorthand, "", followAuthPolicyFlagUsage)
	startCmd.Flags().StringP(inviteWitnessAuthPolicyFlagName, inviteWitnessAuthPolicyFlagShorthand, "", inviteWitnessAuthPolicyFlagUsage)
	startCmd.Flags().StringP(httpTimeoutFlagName, "", "", httpTimeoutFlagUsage)
	startCmd.Flags().StringP(httpDialTimeoutFlagName, "", "", httpDialTimeoutFlagUsage)
	startCmd.Flags().StringP(anchorSyncIntervalFlagName, anchorSyncIntervalFlagShorthand, "", anchorSyncIntervalFlagUsage)
	startCmd.Flags().StringP(anchorSyncAcceleratedIntervalFlagName, "", "", anchorSyncNextIntervalFlagUsage)
	startCmd.Flags().StringP(anchorSyncMaxActivitiesFlagName, "", "", anchorSyncMaxActivitiesFlagUsage)
	startCmd.Flags().StringP(anchorSyncMinActivityAgeFlagName, "", "", anchorSyncMinActivityAgeFlagUsage)
	startCmd.Flags().StringP(vctProofMonitoringIntervalFlagName, "", "", vctProofMonitoringIntervalFlagUsage)
	startCmd.Flags().StringP(vctProofMonitoringExpiryPeriodFlagName, "", "", vctProofMonitoringExpiryPeriodFlagUsage)
	startCmd.Flags().StringP(vctLogMonitoringIntervalFlagName, "", "", vctLogMonitoringIntervalFlagUsage)
	startCmd.Flags().StringP(vctLogMonitoringMaxTreeSizeFlagName, "", "", vctLogMonitoringMaxTreeSizeFlagUsage)
	startCmd.Flags().StringP(vctLogMonitoringGetEntriesRangeFlagName, "", "", vctLogMonitoringGetEntriesRangeFlagUsage)
	startCmd.Flags().StringP(vctLogEntriesStoreEnabledFlagName, "", "", vctLogEntriesStoreEnabledFlagUsage)
	startCmd.Flags().StringP(anchorStatusMonitoringIntervalFlagName, "", "", anchorStatusMonitoringIntervalFlagUsage)
	startCmd.Flags().StringP(anchorStatusInProcessGracePeriodFlagName, "", "", anchorStatusInProcessGracePeriodFlagUsage)
	startCmd.Flags().StringP(witnessPolicyCacheExpirationFlagName, "", "", witnessPolicyCacheExpirationFlagUsage)
	startCmd.Flags().StringP(activityPubClientCacheSizeFlagName, "", "", activityPubClientCacheSizeFlagUsage)
	startCmd.Flags().StringP(activityPubIRICacheSizeFlagName, "", "", activityPubIRICacheSizeFlagUsage)
	startCmd.Flags().StringP(activityPubIRICacheExpirationFlagName, "", "", activityPubIRICacheExpirationFlagUsage)
	startCmd.Flags().StringP(activityPubClientCacheExpirationFlagName, "", "", activityPubClientCacheExpirationFlagUsage)
	startCmd.Flags().StringP(serverIdleTimeoutFlagName, "", "", serverIdleTimeoutFlagUsage)
	startCmd.Flags().StringP(serverReadHeaderTimeoutFlagName, "", "", serverReadHeaderTimeoutFlagUsage)
	startCmd.Flags().StringP(dataURIMediaTypeFlagName, "", "", dataURIMediaTypeFlagUsage)
	startCmd.Flags().String(sidetreeProtocolVersionsFlagName, "", sidetreeProtocolVersionsUsage)
	startCmd.Flags().String(currentSidetreeProtocolVersionFlagName, "", currentSidetreeProtocolVersionUsage)
	startCmd.Flags().StringArray(vcSignKeysIDFlagName, []string{}, vcSignKeysIDFlagUsage)
	startCmd.Flags().StringArray(requestTokensFlagName, []string{}, requestTokensFlagUsage)
	startCmd.Flags().StringP(allowedOriginsCacheExpirationFlagName, "", "", allowedOriginsCacheExpirationFlagUsage)
	startCmd.Flags().String(kmsRegionFlagName, "", kmsRegionFlagUsage)
	startCmd.Flags().StringP(metricsProviderFlagName, "", "", allowedMetricsProviderFlagUsage)
	startCmd.Flags().StringP(promHTTPURLFlagName, "", "", allowedPromHTTPURLFlagNameUsage)
	startCmd.Flags().StringP(tracingProviderFlagName, "", "", tracingProviderFlagUsage)
	startCmd.Flags().StringP(tracingCollectorURLFlagName, "", "", tracingCollectorURLFlagUsage)
	startCmd.Flags().StringP(tracingServiceNameFlagName, "", "", tracingServiceNameFlagUsage)
}
