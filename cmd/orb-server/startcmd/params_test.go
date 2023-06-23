/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/pkg/observability/tracing"
)

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd()

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start orb-server", startCmd.Short)
	require.Equal(t, "Start orb-server", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})

	t.Run("test blank metrics-provider-name arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, "test", "--" + metricsProviderFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "metrics-provider-name value is empty", err.Error())
	})

	t.Run("test blank cas type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + hostURLFlagName, "test",
			"--" + casTypeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "cas-type value is empty", err.Error())
	})

	t.Run("test blank did namespace arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + hostURLFlagName, "test", "--" + casTypeFlagName,
			"local", "--" + didNamespaceFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "did-namespace value is empty", err.Error())
	})

	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + hostURLFlagName, "test", "--" + casTypeFlagName,
			"local", "--" + didNamespaceFlagName,
			"namespace", "--" + databaseTypeFlagName, "", "--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, "mem",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "database-type value is empty", err.Error())
	})
}

func TestAuthTokens(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{
		"--" + authTokensDefFlagName, "/services/orb/keys",
		"--" + authTokensDefFlagName, "/services/orb/outbox|admin&read|admin",
		"--" + authTokensDefFlagName, "/services/orb/inbox||admin",
		"--" + authTokensDefFlagName, "/services/orb/activities|read&",
		"--" + authTokensFlagName, "admin=ADMIN_TOKEN",
		"--" + authTokensFlagName, "read=READ_TOKEN",
	}
	startCmd.SetArgs(args)

	// We don't want to start the server - just initialize the args.
	require.Error(t, startCmd.Execute())

	authDefs, err := getAuthTokenDefinitions(startCmd, authTokensDefFlagName, authTokensDefEnvKey, nil)
	require.NoError(t, err)
	require.Len(t, authDefs, 4)

	require.Equal(t, "/services/orb/keys", authDefs[0].EndpointExpression)
	require.Empty(t, authDefs[0].ReadTokens)
	require.Empty(t, authDefs[0].WriteTokens)

	require.Equal(t, "/services/orb/outbox", authDefs[1].EndpointExpression)
	require.Len(t, authDefs[1].ReadTokens, 2)
	require.Equal(t, authDefs[1].ReadTokens[0], "admin")
	require.Equal(t, authDefs[1].ReadTokens[1], "read")
	require.Len(t, authDefs[1].WriteTokens, 1)
	require.Equal(t, authDefs[1].ReadTokens[0], "admin")

	require.Equal(t, "/services/orb/inbox", authDefs[2].EndpointExpression)
	require.Len(t, authDefs[2].ReadTokens, 0)
	require.Len(t, authDefs[2].WriteTokens, 1)

	require.Equal(t, "/services/orb/activities", authDefs[3].EndpointExpression)
	require.Len(t, authDefs[3].ReadTokens, 1)
	require.Len(t, authDefs[3].WriteTokens, 0)

	authTokens, err := getAuthTokens(startCmd, authTokensFlagName, authTokensEnvKey, nil)
	require.NoError(t, err)
	require.Len(t, authTokens, 2)
	require.Equal(t, "ADMIN_TOKEN", authTokens["admin"])
	require.Equal(t, "READ_TOKEN", authTokens["read"])

	clientAuthDefs, err := getAuthTokenDefinitions(startCmd, clientAuthTokensDefFlagName, clientAuthTokensDefEnvKey, authDefs)
	require.NoError(t, err)
	require.Len(t, clientAuthDefs, len(authDefs))

	clientAuthTokens, err := getAuthTokens(startCmd, clientAuthTokensFlagName, clientAuthTokensEnvKey, authTokens)
	require.NoError(t, err)
	require.Len(t, clientAuthTokens, len(authTokens))
}

func TestRequestTokens(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{
		"--" + requestTokensFlagName, "tk1=value1",
		"--" + requestTokensFlagName, "tk2=value2",
	}
	startCmd.SetArgs(args)

	_ = startCmd.Execute()

	reqTokens := getRequestTokens(startCmd)
	require.Len(t, reqTokens, 2)
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor ORB_HOST_URL (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing cas url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + hostURLFlagName,
			"localhost:8081",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither cas-type (command line flag) nor CAS_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid batch writer timeout", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + casTypeFlagName, "ipfs",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + batchWriterTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid batch writer timeout format")
	})

	t.Run("test invalid max witness delay", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid duration")
	})

	t.Run("test invalid witness store duration", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + witnessStoreExpiryPeriodFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid duration")
	})

	t.Run("test invalid max clock skew", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + maxClockSkewFlagName, "abc",
			"--" + witnessStoreExpiryPeriodFlagName, "1m",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid duration")
	})

	t.Run("test invalid witness store duration - less than maximum witness delay", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + witnessStoreExpiryPeriodFlagName, "5s",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(),
			"witness store expiry period must me greater than maximum witness delay + max clock skew")
	})

	t.Run("test invalid sign with local witness flag", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "1m",
			"--" + signWithLocalWitnessFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for sign-with-local-witness")
	})

	t.Run("test invalid sync time format", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + syncTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for sync-timeout")
	})
	t.Run("test invalid enable-http-signatures", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + httpSignaturesEnabledFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-http-signatures")
	})

	t.Run("test invalid vct enabled flag", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + enableVCTFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-enabled")
	})

	t.Run("test invalid enable-did-discovery", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + enableDidDiscoveryFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-did-discovery")
	})

	t.Run("test invalid enable-unpublished-operation-store", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + enableUnpublishedOperationStoreFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-unpublished-operation-store")
	})

	t.Run("test invalid resolve-from-anchor-origin", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + resolveFromAnchorOriginFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for resolve-from-anchor-origin")
	})

	t.Run("test invalid verify-latest-from-anchor-origin", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + verifyLatestFromAnchorOriginFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for verify-latest-from-anchor-origin")
	})

	t.Run("test invalid include-unpublished-operations-in-metadata", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + includeUnpublishedOperationsFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for include-unpublished-operations-in-metadata")
	})

	t.Run("test invalid include-published-operations-in-metadata", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + includePublishedOperationsFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for include-published-operations-in-metadata")
	})

	t.Run("test invalid enable-maintenance-mode", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + LogLevelFlagName, log.ERROR.String(),
			"--" + maintenanceModeEnabledFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-maintenance-mode")
	})

	t.Run("Invalid ActivityPub page size", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubPageSizeEnvKey, "-125")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()

		require.EqualError(t, err, "activitypub-page-size: value must be greater than 0")
	})

	t.Run("Invalid NodeInfo refresh interval", func(t *testing.T) {
		restoreEnv := setEnv(t, nodeInfoRefreshIntervalEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid IPFS timeout", func(t *testing.T) {
		restoreEnv := setEnv(t, ipfsTimeoutEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid database timeout", func(t *testing.T) {
		restoreEnv := setEnv(t, databaseTimeoutEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid unpublished operation lifespan", func(t *testing.T) {
		restoreEnv := setEnv(t, unpublishedOperationLifespanEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid expiry check interval", func(t *testing.T) {
		restoreEnv := setEnv(t, dataExpiryCheckIntervalEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid max connection channels", func(t *testing.T) {
		restoreEnv := setEnv(t, mqMaxConnectionChannelsEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for mq-max-connection-channels")
	})

	t.Run("Invalid follow auth policy", func(t *testing.T) {
		restoreEnv := setEnv(t, followAuthPolicyEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})

	t.Run("Invalid invite-witness auth policy", func(t *testing.T) {
		restoreEnv := setEnv(t, inviteWitnessAuthPolicyEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})

	t.Run("Invalid anchor sync interval", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorSyncIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for sync-interval [xxx]")
	})

	t.Run("VCT proof monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, vctProofMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-proof-monitoring-interval [xxx]")
	})

	t.Run("VCT proof monitoring max records", func(t *testing.T) {
		restoreEnv := setEnv(t, vctProofMonitoringMaxRecordsEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-proof-monitoring-max-records [xxx]")
	})

	t.Run("VCT proof monitoring expiry period", func(t *testing.T) {
		restoreEnv := setEnv(t, vctProofMonitoringExpiryPeriodEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-proof-monitoring-expiry-period [xxx]")
	})

	t.Run("VCT log monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-log-monitoring-interval [xxx]")
	})

	t.Run("VCT log monitoring max tree size", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringMaxTreeSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-monitoring-max-tree-size: strconv.ParseUint: parsing \"xxx\": invalid syntax")
	})

	t.Run("VCT log monitoring get entries range", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringGetEntriesRangeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-monitoring-get-entries-range: strconv.ParseUint: parsing \"xxx\": invalid syntax")
	})

	t.Run("VCT log monitoring - log entries store enabled", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogEntriesStoreEnabledEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for vct-log-entries-store-enabled")
	})

	t.Run("anchor status monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorStatusMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for anchor-status-monitoring-interval [xxx]")
	})

	t.Run("anchor status max records", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorStatusMaxRecordsEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for anchor-status-max-records [xxx]")
	})

	t.Run("anchor status in-process grace period", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorStatusInProcessGracePeriodEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for anchor-status-in-process-grace-period [xxx]")
	})

	t.Run("witness policy cache expiration", func(t *testing.T) {
		restoreEnv := setEnv(t, witnessPolicyCacheExpirationEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for witness-policy-cache-expiration [xxx]")
	})

	t.Run("ActivityPub client parameters", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubClientCacheSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value [xxx] for parameter [apclient-cache-size]")
	})

	t.Run("ActivityPub IRI cache parameters", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubIRICacheSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value [xxx] for parameter [apiri-cache-size]")
	})

	t.Run("allowed origins cache expiration", func(t *testing.T) {
		restoreEnv := setEnv(t, allowedOriginsCacheExpirationEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for allowed-origins-cache-expiration [xxx]")
	})

	t.Run("allowed DID web domains", func(t *testing.T) {
		restoreEnv := setEnv(t, allowedDIDWebDomainsEnvKey, ":domain.com")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "allowed-did-web-domains: parse \":domain.com\": missing protocol scheme")
	})

	t.Run("anchor ref pending record lifespan", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorRefPendingRecordLifespanEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for anchor-ref-pending-record-lifespan [xxx]")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd()

		t.Setenv(hostURLEnvKey, "")

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "ORB_HOST_URL value is empty", err.Error())
	})

	t.Run("test blank cas url env var", func(t *testing.T) {
		startCmd := GetStartCmd()

		t.Setenv(hostURLEnvKey, "localhost:8080")
		t.Setenv(promHTTPURLEnvKey, "localhost:8081")
		t.Setenv(casTypeEnvKey, "")

		defer func() {
			require.NoError(t, os.Unsetenv(hostURLEnvKey))
			require.NoError(t, os.Unsetenv(casTypeEnvKey))
		}()

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "CAS_TYPE value is empty", err.Error())
	})
}

func TestStartCmdWithInvalidCIDVersion(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + metricsProviderFlagName, "prometheus",
		"--" + promHTTPURLFlagName, "localhost:8248",
		"--" + externalEndpointFlagName, "orb.example.com",
		"--" + ipfsURLFlagName, "localhost:8081",
		"--" + casTypeFlagName, "ipfs",
		"--" + cidVersionFlagName, "-1",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "1m",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
		"--" + anchorCredentialDomainFlagName, "domain.com",
		"--" + LogLevelFlagName, log.ERROR.String(),
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, "invalid CID version specified. Must be either 0 or 1")
}

func TestStartCmdCreateKMSFailure(t *testing.T) {
	t.Run("KMS fails (DB)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + kmsSecretsDatabaseURLFlagName, "badURL",
			"--" + kmsTypeFlagName, "local",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB")
	})

	t.Run("KMS wrong mode", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + kmsSecretsDatabaseURLFlagName, "badURL",
			"--" + kmsTypeFlagName, "wrong",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "unsupported kms type: wrong")
	})

	t.Run("KMS fails (create kid)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + kmsTypeFlagName, "web",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "init config value for")
	})

	t.Run("KMS fails (create remote store)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHTTPURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + kmsEndpointFlagName, "https://vct.example.com",
			"--" + kmsTypeFlagName, "web",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "init config value for \"web-key-store\"")
	})
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	t.Run("CAS Type: IPFS", func(t *testing.T) {
		startCmd := GetStartCmd()

		setEnvVars(t, databaseTypeMemOption, "ipfs", "false")

		defer unsetEnvVars(t)

		go func() {
			require.NoError(t, startCmd.Execute())
		}()

		require.NoError(t, backoff.Retry(func() error {
			_, err := net.DialTimeout("tcp", os.Getenv(hostURLEnvKey), time.Second)

			return err
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5)))
		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	})
	t.Run("CAS Type: Local (without IPFS replication)", func(t *testing.T) {
		startCmd := GetStartCmd()

		setEnvVars(t, databaseTypeMemOption, "local", "false")

		defer unsetEnvVars(t)

		go func() {
			require.NoError(t, startCmd.Execute())
		}()

		require.NoError(t, backoff.Retry(func() error {
			_, err := net.DialTimeout("tcp", os.Getenv(hostURLEnvKey), time.Second)

			return err
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5)))
		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	})
	t.Run("CAS Type: Local (with IPFS replication)", func(t *testing.T) {
		startCmd := GetStartCmd()

		setEnvVars(t, databaseTypeMemOption, "local", "true")

		defer unsetEnvVars(t)

		go func() {
			require.NoError(t, startCmd.Execute())
		}()

		require.NoError(t, backoff.Retry(func() error {
			_, err := net.DialTimeout("tcp", os.Getenv(hostURLEnvKey), time.Second)

			return err
		}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5)))
		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	})
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("IPFS configured and CAS type is local", func(t *testing.T) {
		t.Run("Database type is mem", func(t *testing.T) {
			startCmd := GetStartCmd()

			startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false",
				databaseTypeMemOption))

			go func() {
				err := startCmd.Execute()
				require.Nil(t, err)
				require.Equal(t, log.ERROR, log.GetLevel(""))
			}()

			time.Sleep(50 * time.Millisecond)

			require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
		})
		t.Run("Database type is MongoDB", func(t *testing.T) {
			t.Run("Fail to create MongoDB client", func(t *testing.T) {
				startCmd := GetStartCmd()

				startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false",
					databaseTypeMongoDBOption))

				err := startCmd.Execute()
				require.EqualError(t, err,
					"create MongoDB storage provider: failed to create a new MongoDB client: "+
						`error parsing uri: scheme must be "mongodb" or "mongodb+srv"`)
			})
		})
	})
	t.Run("IPFS configured, CAS type is local, but IPFS node is ipfs.io and replication "+
		"is enabled. Replication is forced off since ipfs.io doesn't support writes", func(t *testing.T) {
		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("https://ipfs.io", "local", "true", databaseTypeMemOption))

		go func() {
			err := startCmd.Execute()
			require.Nil(t, err)
			require.Equal(t, log.ERROR, log.GetLevel(""))
		}()

		time.Sleep(50 * time.Millisecond)

		require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
	})
}

func TestStartCmdWithConflictingIPFSAndCASTypeSettings(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(getTestArgs("https://ipfs.io", "ipfs", "false", databaseTypeMemOption))

	err := startCmd.Execute()
	require.EqualError(t, err, "CAS type cannot be set to IPFS if ipfs.io is being used as the node "+
		"since it doesn't support writes. Either switch the node URL to one that does support writes or "+
		"change the CAS type to local")
}

func TestStartCmdWithUnparsableIPFSURL(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(getTestArgs("%s", "ipfs", "false", databaseTypeMemOption))

	err := startCmd.Execute()
	require.EqualError(t, err, `failed to parse IPFS URL: parse "%s": invalid URL escape "%s"`)
}

func TestStartCmdWithInvalidCASType(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(getTestArgs("localhost:8081", "InvalidName", "false", databaseTypeMemOption))

	err := startCmd.Execute()
	require.EqualError(t, err, "InvalidName is not a valid CAS type. It must be either local or ipfs")
}

func TestGetActivityPubPageSize(t *testing.T) {
	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		pageSize, err := getActivityPubPageSize(cmd)
		require.NoError(t, err)
		require.Equal(t, defaultActivityPubPageSize, pageSize)
	})

	t.Run("Invalid value -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+activityPubPageSizeFlagName, "xxx")

		_, err := getActivityPubPageSize(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("<=0 -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+activityPubPageSizeFlagName, "-120")

		_, err := getActivityPubPageSize(cmd)
		require.EqualError(t, err, "value must be greater than 0")
	})

	t.Run("Valid value -> success", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+activityPubPageSizeFlagName, "120")

		pageSize, err := getActivityPubPageSize(cmd)
		require.NoError(t, err)
		require.Equal(t, 120, pageSize)
	})

	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubPageSizeEnvKey, "125")
		defer restoreEnv()

		cmd := getTestCmd(t)

		pageSize, err := getActivityPubPageSize(cmd)
		require.NoError(t, err)
		require.Equal(t, 125, pageSize)
	})
}

func TestGetIPFSTimeout(t *testing.T) {
	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		timeout, err := cmdutil.GetDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.NoError(t, err)
		require.Equal(t, defaultIPFSTimeout, timeout)
	})

	t.Run("Invalid value -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "xxx")

		_, err := cmdutil.GetDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Valid value -> success", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "30s")

		timeout, err := cmdutil.GetDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.NoError(t, err)
		require.Equal(t, 30*time.Second, timeout)
	})

	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, ipfsTimeoutEnvKey, "40s")
		defer restoreEnv()

		cmd := getTestCmd(t)

		timeout, err := cmdutil.GetDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.NoError(t, err)
		require.Equal(t, 40*time.Second, timeout)
	})
}

func TestGetMQParameters(t *testing.T) {
	const u = "amqp://admin:password@orb.mq.domain1.com:5672/"

	t.Run("Valid env values -> error", func(t *testing.T) {
		restoreURLEnv := setEnv(t, mqURLEnvKey, u)
		restoreObserverPoolEnv := setEnv(t, mqObserverPoolEnvKey, "3")
		restoreOutboxPoolEnv := setEnv(t, mqOutboxPoolEnvKey, "4")
		restoreInboxPoolEnv := setEnv(t, mqInboxPoolEnvKey, "7")
		restoreOpQueuePoolEnv := setEnv(t, mqOPQueuePoolEnvKey, "8")
		restoreAnchorLinksetPoolEnv := setEnv(t, mqAnchorLinksetPoolEnvKey, "9")
		restoreChannelPoolEnv := setEnv(t, mqPublisherChannelPoolSizeEnvKey, "321")
		restoreConfirmDeliveryEnv := setEnv(t, mqPublisherConfirmDeliveryEnvKey, "false")
		restoreConnectionSubscriptionsEnv := setEnv(t, mqMaxConnectionChannelsEnvKey, "456")
		restoreConnectionRetriesEnv := setEnv(t, mqConnectMaxRetriesEnvKey, "12")
		restoreRedeliveryMaxAttempts := setEnv(t, mqRedeliveryMaxAttemptsEnvKey, "17")
		restoreRedeliveryMultiplier := setEnv(t, mqRedeliveryMultiplierEnvKey, "1.7")
		restoreRedeliveryInitialInterval := setEnv(t, mqRedeliveryInitialIntervalEnvKey, "3s")
		restoreRedeliveryMaxInterval := setEnv(t, mqRedeliveryMaxIntervalEnvKey, "35s")

		defer func() {
			restoreURLEnv()
			restoreObserverPoolEnv()
			restoreOutboxPoolEnv()
			restoreInboxPoolEnv()
			restoreOpQueuePoolEnv()
			restoreAnchorLinksetPoolEnv()
			restoreConnectionSubscriptionsEnv()
			restoreChannelPoolEnv()
			restoreConfirmDeliveryEnv()
			restoreConnectionRetriesEnv()
			restoreRedeliveryMaxAttempts()
			restoreRedeliveryMultiplier()
			restoreRedeliveryInitialInterval()
			restoreRedeliveryMaxInterval()
		}()

		cmd := getTestCmd(t)

		mqParams, err := getMQParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, u, mqParams.endpoint)
		require.Equal(t, 3, mqParams.observerPoolSize)
		require.Equal(t, 4, mqParams.outboxPoolSize)
		require.Equal(t, 7, mqParams.inboxPoolSize)
		require.Equal(t, 8, mqParams.opQueuePoolSize)
		require.Equal(t, 9, mqParams.anchorLinksetPoolSize)
		require.Equal(t, 456, mqParams.maxConnectionChannels)
		require.Equal(t, 321, mqParams.publisherChannelPoolSize)
		require.False(t, mqParams.publisherConfirmDelivery)
		require.Equal(t, 12, mqParams.maxConnectRetries)
		require.Equal(t, 17, mqParams.maxRedeliveryAttempts)
		require.Equal(t, 1.7, mqParams.redeliveryMultiplier)
		require.Equal(t, 3*time.Second, mqParams.redeliveryInitialInterval)
		require.Equal(t, 35*time.Second, mqParams.maxRedeliveryInterval)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		restoreURLEnv := setEnv(t, mqURLEnvKey, u)
		defer restoreURLEnv()

		cmd := getTestCmd(t)

		mqParams, err := getMQParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, u, mqParams.endpoint)
		require.Equal(t, mqDefaultObserverPoolSize, mqParams.observerPoolSize)
		require.Equal(t, mqDefaultOutboxPoolSize, mqParams.outboxPoolSize)
		require.Equal(t, mqDefaultInboxPoolSize, mqParams.inboxPoolSize)
		require.Equal(t, mqDefaultOpQueuePoolSize, mqParams.opQueuePoolSize)
		require.Equal(t, mqDefaultAnchorLinksetPoolSize, mqParams.anchorLinksetPoolSize)
		require.Equal(t, mqDefaultMaxConnectionSubscriptions, mqParams.maxConnectionChannels)
		require.Equal(t, mqDefaultPublisherChannelPoolSize, mqParams.publisherChannelPoolSize)
		require.Equal(t, mqDefaultPublisherConfirmDelivery, mqParams.publisherConfirmDelivery)
		require.Equal(t, mqDefaultRedeliveryMaxInterval, mqParams.maxRedeliveryInterval)
		require.Equal(t, mqDefaultRedeliveryInitialInterval, mqParams.redeliveryInitialInterval)
		require.Equal(t, mqDefaultRedeliveryMaxAttempts, mqParams.maxRedeliveryAttempts)
		require.Equal(t, mqDefaultRedeliveryMultiplier, mqParams.redeliveryMultiplier)
	})

	t.Run("Invalid max connection subscriptions value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqMaxConnectionChannelsEnvKey, "xxx")

		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid publisher channel pool value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqPublisherChannelPoolSizeEnvKey, "xxx")

		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid publisher confirm delivery -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqPublisherConfirmDeliveryEnvKey, "xxx")

		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid op queue pool size value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqOPQueuePoolEnvKey, "xxx")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid anchor linkset pool size value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqAnchorLinksetPoolEnvKey, "xxx")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})
}

func TestGetOpQueueParameters(t *testing.T) {
	t.Run("Valid env values -> error", func(t *testing.T) {
		restoreTaskMonitorIntervalEnv := setEnv(t, opQueueTaskMonitorIntervalEnvKey, "17s")
		restoreTaskExpirationEnv := setEnv(t, opQueueTaskExpirationEnvKey, "33s")
		restoreMaxOperationsToRepostEnv := setEnv(t, opQueueMaxOperationsToRepostEnvKey, "750")
		restoreOperationLifespanEnv := setEnv(t, opQueueOperationLifespanEnvKey, "60s")
		restoreMaxContiguousOperationsWithErrEnv := setEnv(t, opQueueMaxContiguousOperationsWithErrEnvKey, "12")
		restoreMaxContiguousOperationsWithoutErrEnv := setEnv(t, opQueueMaxContiguousOperationsWithoutErrEnvKey, "13")

		defer func() {
			restoreTaskExpirationEnv()
			restoreTaskMonitorIntervalEnv()
			restoreMaxOperationsToRepostEnv()
			restoreOperationLifespanEnv()
			restoreMaxContiguousOperationsWithErrEnv()
			restoreMaxContiguousOperationsWithoutErrEnv()
		}()

		cmd := getTestCmd(t)

		opQueueParams, err := getOpQueueParameters(cmd,
			&mqParams{
				redeliveryMultiplier:      2.5,
				redeliveryInitialInterval: 4 * time.Second,
				maxRedeliveryInterval:     3 * time.Minute,
				maxRedeliveryAttempts:     23,
				opQueuePoolSize:           221,
			},
		)
		require.NoError(t, err)
		require.Equal(t, 221, opQueueParams.PoolSize)
		require.Equal(t, 17*time.Second, opQueueParams.TaskMonitorInterval)
		require.Equal(t, 33*time.Second, opQueueParams.TaskExpiration)
		require.Equal(t, 23, opQueueParams.MaxRetries)
		require.Equal(t, 4*time.Second, opQueueParams.RetriesInitialDelay)
		require.Equal(t, 3*time.Minute, opQueueParams.RetriesMaxDelay)
		require.Equal(t, float64(2.5), opQueueParams.RetriesMultiplier)
		require.Equal(t, 750, opQueueParams.MaxOperationsToRepost)
		require.Equal(t, 60*time.Second, opQueueParams.OperationLifeSpan)
		require.Equal(t, 12, opQueueParams.MaxContiguousWithError)
		require.Equal(t, 13, opQueueParams.MaxContiguousWithoutError)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		opQueueParams, err := getOpQueueParameters(cmd, &mqParams{})
		require.NoError(t, err)
		require.Equal(t, opQueueDefaultTaskMonitorInterval, opQueueParams.TaskMonitorInterval)
		require.Equal(t, opQueueDefaultTaskExpiration, opQueueParams.TaskExpiration)
		require.Equal(t, opQueueDefaultMaxOperationsToRepost, opQueueParams.MaxOperationsToRepost)
		require.Equal(t, opQueueDefaultOperationLifespan, opQueueParams.OperationLifeSpan)
		require.Equal(t, opQueueDefaultMaxContiguousOperationsWithErr, opQueueParams.MaxContiguousWithError)
		require.Equal(t, opQueueDefaultMaxContiguousOperationsWithoutErr, opQueueParams.MaxContiguousWithoutError)
	})

	t.Run("Invalid task monitor interval value -> error", func(t *testing.T) {
		restoreTaskMonitorIntervalEnv := setEnv(t, opQueueTaskMonitorIntervalEnvKey, "17")
		defer restoreTaskMonitorIntervalEnv()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid task expiration value -> error", func(t *testing.T) {
		restoreTaskExpirationEnv := setEnv(t, opQueueTaskExpirationEnvKey, "33")
		defer restoreTaskExpirationEnv()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid operation lifespan value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, opQueueOperationLifespanEnvKey, "17")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid max operation to respost value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, opQueueMaxOperationsToRepostEnvKey, "xxx")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})
}

func TestCreateActivityPubStore(t *testing.T) {
	t.Run("Fail to create CouchDB provider", func(t *testing.T) {
		errExpected := errors.New("injected open store error")

		p := &mockStoreProvider{}
		p.ErrOpenStoreHandle = errExpected

		activityPubStore, err := createActivityPubStore(
			&storageProvider{p, databaseTypeCouchDBOption},
			"serviceEndpoint")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, activityPubStore)
	})
	t.Run("Fail to create ActivityPub store using MongoDB", func(t *testing.T) {
		errExpected := errors.New("injected open store error")

		p := &mockStoreProvider{}
		p.ErrOpenStoreHandle = errExpected

		activityPubStore, err := createActivityPubStore(
			&storageProvider{p, databaseTypeMongoDBOption},
			"serviceEndpoint")
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, activityPubStore)
	})
	t.Run("MemDB -> success", func(t *testing.T) {
		p := ariesmemstorage.NewProvider()

		activityPubStore, err := createActivityPubStore(
			&storageProvider{p, databaseTypeMemOption},
			"serviceEndpoint")
		require.NoError(t, err)
		require.NotNil(t, activityPubStore)
	})
}

func TestGetFollowAuthParameters(t *testing.T) {
	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, followAuthPolicyEnvKey, string(acceptListPolicy))
		defer restoreEnv()

		cmd := getTestCmd(t)

		policy, err := getFollowAuthPolicy(cmd)
		require.NoError(t, err)
		require.Equal(t, acceptListPolicy, policy)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		policy, err := getFollowAuthPolicy(cmd)
		require.NoError(t, err)
		require.Equal(t, acceptAllPolicy, policy)
	})

	t.Run("Invalid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, followAuthPolicyEnvKey, "invalid-policy")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getFollowAuthPolicy(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})
}

func TestGetInviteWitnessAuthParameters(t *testing.T) {
	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, inviteWitnessAuthPolicyEnvKey, string(acceptListPolicy))
		defer restoreEnv()

		cmd := getTestCmd(t)

		policy, err := getInviteWitnessAuthPolicy(cmd)
		require.NoError(t, err)
		require.Equal(t, acceptListPolicy, policy)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		policy, err := getInviteWitnessAuthPolicy(cmd)
		require.NoError(t, err)
		require.Equal(t, acceptAllPolicy, policy)
	})

	t.Run("Invalid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, inviteWitnessAuthPolicyEnvKey, "invalid-policy")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getInviteWitnessAuthPolicy(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})
}

func TestGetActivityPubClientParameters(t *testing.T) {
	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreSizeEnv := setEnv(t, activityPubClientCacheSizeEnvKey, "1000")
		restoreExpiryEnv := setEnv(t, activityPubClientCacheExpirationEnvKey, "10m")

		defer func() {
			restoreSizeEnv()
			restoreExpiryEnv()
		}()

		cmd := getTestCmd(t)

		size, expiry, err := getActivityPubClientParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, 1000, size)
		require.Equal(t, 10*time.Minute, expiry)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		size, expiry, err := getActivityPubClientParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, defaultActivityPubClientCacheSize, size)
		require.Equal(t, defaultActivityPubClientCacheExpiration, expiry)
	})

	t.Run("Invalid env value -> error", func(t *testing.T) {
		t.Run("Invalid number for cache size", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubClientCacheSizeEnvKey, "invalid")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubClientParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid value [invalid] for parameter [apclient-cache-size]")
		})

		t.Run("Cache size less than 0", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubClientCacheSizeEnvKey, "-1")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubClientParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "value for parameter [apclient-cache-size] must be grater than 0")
		})

		t.Run("Invalid cache expiry", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubClientCacheExpirationEnvKey, "invalid")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubClientParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid value for parameter [apclient-cache-Expiration]")
		})
	})
}

func TestGetActivityPubIRICacheParameters(t *testing.T) {
	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreSizeEnv := setEnv(t, activityPubIRICacheSizeEnvKey, "1000")
		restoreExpiryEnv := setEnv(t, activityPubIRICacheExpirationEnvKey, "10m")

		defer func() {
			restoreSizeEnv()
			restoreExpiryEnv()
		}()

		cmd := getTestCmd(t)

		size, expiry, err := getActivityPubIRICacheParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, 1000, size)
		require.Equal(t, 10*time.Minute, expiry)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		size, expiry, err := getActivityPubIRICacheParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, defaultActivityPubIRICacheSize, size)
		require.Equal(t, defaultActivityPubIRICacheExpiration, expiry)
	})

	t.Run("Invalid env value -> error", func(t *testing.T) {
		t.Run("Invalid number for cache size", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubIRICacheSizeEnvKey, "invalid")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubIRICacheParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid value [invalid] for parameter [apiri-cache-size]")
		})

		t.Run("Cache size less than 0", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubIRICacheSizeEnvKey, "-1")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubIRICacheParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "value for parameter [apiri-cache-size] must be grater than 0")
		})

		t.Run("Invalid cache expiry", func(t *testing.T) {
			restoreEnv := setEnv(t, activityPubIRICacheExpirationEnvKey, "invalid")
			defer restoreEnv()

			cmd := getTestCmd(t)

			_, _, err := getActivityPubIRICacheParameters(cmd)
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid value for parameter [apiri-cache-Expiration]")
		})
	})
}

func TestTracingParameters(t *testing.T) {
	t.Run("Default (not enabled)", func(t *testing.T) {
		cmd := getTestCmd(t)

		params, err := getTracingParams(cmd)
		require.NoError(t, err)
		require.False(t, params.enabled)
	})

	t.Run("Jaeger provider, no URL -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, tracingProviderEnvKey, tracing.ProviderJaeger)
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getTracingParams(cmd)
		require.EqualError(t, err, "Neither tracing-collector-url (command line flag) nor ORB_TRACING_COLLECTOR_URL (environment variable) have been set.")
	})

	t.Run("Unsupported provider -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, tracingProviderEnvKey, "some-other-provider")
		defer restoreEnv()

		cmd := getTestCmd(t)

		_, err := getTracingParams(cmd)
		require.EqualError(t, err, "unsupported tracing provider: some-other-provider")
	})

	t.Run("Jaeger provider -> success", func(t *testing.T) {
		const (
			url     = "https://localhost:9000/jaeger"
			service = "service1"
		)

		restoreProviderEnv := setEnv(t, tracingProviderEnvKey, tracing.ProviderJaeger)
		restoreURLEnv := setEnv(t, tracingCollectorURLEnvKey, url)
		restoreServiceEnv := setEnv(t, tracingServiceNameEnvKey, service)

		defer func() {
			restoreProviderEnv()
			restoreURLEnv()
			restoreServiceEnv()
		}()

		cmd := getTestCmd(t)

		params, err := getTracingParams(cmd)
		require.NoError(t, err)
		require.Equal(t, tracing.ProviderJaeger, params.provider)
		require.Equal(t, url, params.collectorURL)
		require.Equal(t, service, params.serviceName)
	})
}

func setEnvVars(t *testing.T, databaseType, casType, replicateLocalCASToIPFS string) {
	t.Helper()

	t.Setenv(hostURLEnvKey, "localhost:8237")
	t.Setenv(enableVCTFlagName, "true")
	t.Setenv(casTypeEnvKey, casType)
	t.Setenv(localCASReplicateInIPFSEnvKey, replicateLocalCASToIPFS)
	t.Setenv(batchWriterTimeoutEnvKey, "2000")
	t.Setenv(maxWitnessDelayEnvKey, "10m")
	t.Setenv(witnessStoreExpiryPeriodEnvKey, "12m")
	t.Setenv(signWithLocalWitnessEnvKey, "true")
	t.Setenv(didNamespaceEnvKey, "namespace")
	t.Setenv(databaseTypeEnvKey, databaseType)
	t.Setenv(kmsSecretsDatabaseTypeEnvKey, databaseTypeMemOption)
	t.Setenv(anchorCredentialDomainEnvKey, "domain")
	t.Setenv(enableUnpublishedOperationStoreEnvKey, "true")
	t.Setenv(sidetreeProtocolVersionsEnvKey, "1.0")
	t.Setenv(currentSidetreeProtocolVersionEnvKey, "1.0")
	t.Setenv(kmsTypeEnvKey, "local")
	t.Setenv(kmsSecretsDatabaseTypeFlagName, "mem")
	t.Setenv(maintenanceModeEnabledEnvKey, "false")
}

//nolint:gocritic
func unsetEnvVars(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsSecretsDatabasePrefixEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func getTestCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	createFlags(cmd)

	cmd.SetArgs(args)

	require.NoError(t, cmd.Execute())

	return cmd
}

func setEnv(t *testing.T, name, value string) (restore func()) {
	t.Helper()
	t.Setenv(name, value)

	return func() {
		require.NoError(t, os.Unsetenv(name))
	}
}

func getTestArgs(ipfsURL, casType, localCASReplicateInIPFSEnabled, databaseType string) []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + metricsProviderFlagName, "prometheus",
		"--" + promHTTPURLFlagName, "localhost:8248",
		"--" + externalEndpointFlagName, "orb.example.com",
		"--" + discoveryDomainFlagName, "shared.example.com",
		"--" + enableVCTFlagName, "true",
		"--" + ipfsURLFlagName, ipfsURL,
		"--" + cidVersionFlagName, "0",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "1m",
		"--" + witnessStoreExpiryPeriodFlagName, "5m",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + casTypeFlagName, casType,
		"--" + didNamespaceFlagName, "namespace",
		"--" + databaseTypeFlagName, databaseType,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseType,
		"--" + anchorCredentialDomainFlagName, "domain.com",
		"--" + LogLevelFlagName, log.ERROR.String(),
		"--" + localCASReplicateInIPFSFlagName, localCASReplicateInIPFSEnabled,
		"--" + enableUnpublishedOperationStoreFlagName, "true",
		"--" + unpublishedOperationStoreOperationTypesFlagName, "update",
		"--" + includePublishedOperationsFlagName, "true",
		"--" + includeUnpublishedOperationsFlagName, "true",
		"--" + resolveFromAnchorOriginFlagName, "true",
		"--" + verifyLatestFromAnchorOriginFlagName, "true",
		"--" + sidetreeProtocolVersionsFlagName, "1.0",
		"--" + currentSidetreeProtocolVersionFlagName, "1.0",
		"--" + kmsTypeFlagName, "local",
		"--" + maintenanceModeEnabledFlagName, "false",
	}
}

func Test_getAPServiceParams(t *testing.T) {
	t.Run("Default service ID", func(t *testing.T) {
		apServiceParams, err := newAPServiceParams("", "https://orb.domain1.com", nil, false)
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain1.com/services/orb", apServiceParams.serviceEndpoint().String())
		require.Equal(t, "https://orb.domain1.com/services/orb", apServiceParams.serviceIRI().String())
		require.Equal(t, "https://orb.domain1.com/services/orb/keys/main-key", apServiceParams.publicKeyIRI())
	})

	t.Run("HTTPS service ID -> success", func(t *testing.T) {
		apServiceParams, err := newAPServiceParams("https://orb.domain1.com/services/anchor",
			"https://orb.domain1.com", nil, false)
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain1.com/services/anchor", apServiceParams.serviceEndpoint().String())
		require.Equal(t, "https://orb.domain1.com/services/anchor", apServiceParams.serviceIRI().String())
		require.Equal(t, "https://orb.domain1.com/services/anchor/keys/main-key", apServiceParams.publicKeyIRI())
	})

	t.Run("DID service ID -> success", func(t *testing.T) {
		apServiceParams, err := newAPServiceParams("did:web:orb.domain1.com:services:anchor",
			"https://orb.domain1.com", &kmsParameters{httpSignActiveKeyID: "123456"}, false)
		require.NoError(t, err)
		require.Equal(t, "https://orb.domain1.com/services/anchor", apServiceParams.serviceEndpoint().String())
		require.Equal(t, "did:web:orb.domain1.com:services:anchor", apServiceParams.serviceIRI().String())
		require.Equal(t, "did:web:orb.domain1.com:services:anchor#123456", apServiceParams.publicKeyIRI())
	})

	t.Run("DID service ID with dev-mode -> success", func(t *testing.T) {
		apServiceParams, err := newAPServiceParams("did:web:orb.domain1.com:services:anchor",
			"http://orb.domain1.com", &kmsParameters{httpSignActiveKeyID: "123456"}, true)
		require.NoError(t, err)
		require.Equal(t, "http://orb.domain1.com/services/anchor", apServiceParams.serviceEndpoint().String())
		require.Equal(t, "did:web:orb.domain1.com:services:anchor", apServiceParams.serviceIRI().String())
		require.Equal(t, "did:web:orb.domain1.com:services:anchor#123456", apServiceParams.publicKeyIRI())
	})

	t.Run("serviceID/external-endpoint protocol mismatch -> error", func(t *testing.T) {
		_, err := newAPServiceParams("http://orb.domain1.com/services/anchor",
			"https://orb.domain1.com", nil, false)
		require.EqualError(t, err, "external endpoint [https://orb.domain1.com] and service ID [http://orb.domain1.com/services/anchor] must have the same protocol scheme (e.g. https)")
	})

	t.Run("serviceID/external-endpoint host mismatch -> error", func(t *testing.T) {
		_, err := newAPServiceParams("did:web:orb.domain1.com:services:anchor",
			"https://orb.domainx.com", &kmsParameters{httpSignActiveKeyID: "123456"}, false)
		require.EqualError(t, err, "external endpoint [https://orb.domainx.com] and service ID [did:web:orb.domain1.com:services:anchor] must have the same host")
	})

	t.Run("Invalid DID format -> error", func(t *testing.T) {
		_, err := newAPServiceParams("did:web",
			"https://orb.domainx.com", &kmsParameters{httpSignActiveKeyID: "123456"}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did")
	})

	t.Run("DID method not supported -> error", func(t *testing.T) {
		_, err := newAPServiceParams("did:key:orb.domain1.com:services:anchor",
			"https://orb.domainx.com", &kmsParameters{httpSignActiveKeyID: "123456"}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported DID method [did:key]")
	})
}

type mockStoreProvider struct {
	ErrOpenStoreHandle error
	ErrSetStoreConfig  error
	ErrClose           error
	ErrCloseStore      error
	FailNamespace      string
}

// OpenStore opens and returns a store for given name space.
func (s *mockStoreProvider) OpenStore(name string) (storage.Store, error) {
	return nil, s.ErrOpenStoreHandle
}

// SetStoreConfig always return a nil error.
func (s *mockStoreProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return s.ErrSetStoreConfig
}

// GetStoreConfig is not implemented.
func (s *mockStoreProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

// GetOpenStores is not implemented.
func (s *mockStoreProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

// Close closes all stores created under this store provider.
func (s *mockStoreProvider) Close() error {
	return s.ErrClose
}

// CloseStore closes store for given name space.
func (s *mockStoreProvider) CloseStore(name string) error {
	return s.ErrCloseStore
}

// Ping db.
func (s *mockStoreProvider) Ping() error {
	return nil
}
