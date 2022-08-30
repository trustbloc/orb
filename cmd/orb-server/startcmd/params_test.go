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

	backoff "github.com/cenkalti/backoff/v4"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
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

	t.Run("test blank host metrics url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, "test", "--" + hostMetricsURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-metrics-url value is empty", err.Error())
	})

	t.Run("test blank cas type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + hostMetricsURLFlagName, "test",
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
			"--" + hostURLFlagName, "test", "--" + hostMetricsURLFlagName, "test", "--" + casTypeFlagName,
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
			"--" + hostURLFlagName, "test", "--" + hostMetricsURLFlagName, "test", "--" + casTypeFlagName,
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

	err := startCmd.Execute()

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
			"--" + hostURLFlagName, "localhost:8080", "--" + hostMetricsURLFlagName,
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + casTypeFlagName, "ipfs",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + batchWriterTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + witnessStoreExpiryPeriodFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + maxClockSkewFlagName, "abc",
			"--" + witnessStoreExpiryPeriodFlagName, "1m",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "10s",
			"--" + witnessStoreExpiryPeriodFlagName, "5s",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "1m",
			"--" + signWithLocalWitnessFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid sign with local witness flag value")
	})

	t.Run("test invalid sync time format", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + syncTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "sync timeout is not a number(positive)")
	})
	t.Run("test invalid enable-http-signatures", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
			"--" + includePublishedOperationsFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for include-published-operations-in-metadata")
	})

	t.Run("Invalid ActivityPub page size", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubPageSizeEnvKey, "-125")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()

		require.EqualError(t, err, "activitypub-page-size: value must be greater than 0")
	})

	t.Run("Invalid NodeInfo refresh interval", func(t *testing.T) {
		restoreEnv := setEnv(t, nodeInfoRefreshIntervalEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid IPFS timeout", func(t *testing.T) {
		restoreEnv := setEnv(t, ipfsTimeoutEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid database timeout", func(t *testing.T) {
		restoreEnv := setEnv(t, databaseTimeoutEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid unpublished operation lifespan", func(t *testing.T) {
		restoreEnv := setEnv(t, unpublishedOperationLifespanEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid expiry check interval", func(t *testing.T) {
		restoreEnv := setEnv(t, dataExpiryCheckIntervalEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
	})

	t.Run("Invalid max connection channels", func(t *testing.T) {
		restoreEnv := setEnv(t, mqMaxConnectionChannelsEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for mq-max-connection-channels")
	})

	t.Run("Invalid follow auth policy", func(t *testing.T) {
		restoreEnv := setEnv(t, followAuthPolicyEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})

	t.Run("Invalid invite-witness auth policy", func(t *testing.T) {
		restoreEnv := setEnv(t, inviteWitnessAuthPolicyEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported accept/reject authorization type")
	})

	t.Run("Invalid anchor sync interval", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorSyncIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "sync-interval: invalid value [xxx]")
	})

	t.Run("VCT proof monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, vctProofMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-proof-monitoring-interval: invalid value [xxx]")
	})

	t.Run("VCT proof monitoring expiry period", func(t *testing.T) {
		restoreEnv := setEnv(t, vctProofMonitoringExpiryPeriodEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-proof-monitoring-expiry-period: invalid value [xxx]")
	})

	t.Run("VCT log monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-monitoring-interval: invalid value [xxx]")
	})

	t.Run("VCT log monitoring max tree size", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringMaxTreeSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-monitoring-max-tree-size: strconv.ParseUint: parsing \"xxx\": invalid syntax")
	})

	t.Run("VCT log monitoring get entries range", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogMonitoringGetEntriesRangeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-monitoring-get-entries-range: strconv.ParseUint: parsing \"xxx\": invalid syntax")
	})

	t.Run("VCT log monitoring - log entries store enabled", func(t *testing.T) {
		restoreEnv := setEnv(t, vctLogEntriesStoreEnabledEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "vct-log-entries-store-enabled: strconv.ParseBool: parsing \"xxx\": invalid syntax")
	})

	t.Run("anchor status monitoring interval", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorStatusMonitoringIntervalEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor-status-monitoring-interval: invalid value [xxx]")
	})

	t.Run("anchor status in-process grace period", func(t *testing.T) {
		restoreEnv := setEnv(t, anchorStatusInProcessGracePeriodEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "anchor-status-in-process-grace-period: invalid value [xxx]")
	})

	t.Run("witness policy cache expiration", func(t *testing.T) {
		restoreEnv := setEnv(t, witnessPolicyCacheExpirationEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "witness-policy-cache-expiration: invalid value [xxx]")
	})

	t.Run("ActivityPub client parameters", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubClientCacheSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value [xxx] for parameter [apclient-cache-size]")
	})

	t.Run("ActivityPub IRI cache parameters", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubIRICacheSizeEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value [xxx] for parameter [apiri-cache-size]")
	})

	t.Run("allowed origins cache expiration", func(t *testing.T) {
		restoreEnv := setEnv(t, allowedOriginsCacheExpirationEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "allowed-origins-cache-expiration: invalid value [xxx]")
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd()

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "ORB_HOST_URL value is empty", err.Error())
	})

	t.Run("test blank cas url env var", func(t *testing.T) {
		startCmd := GetStartCmd()

		err := os.Setenv(hostURLEnvKey, "localhost:8080")
		require.NoError(t, err)

		err = os.Setenv(hostMetricsURLEnvKey, "localhost:8081")
		require.NoError(t, err)

		err = os.Setenv(casTypeEnvKey, "")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, os.Unsetenv(hostURLEnvKey))
			require.NoError(t, os.Unsetenv(casTypeEnvKey))
		}()

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "CAS_TYPE value is empty", err.Error())
	})
}

func TestStartCmdWithInvalidCIDVersion(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + hostMetricsURLFlagName, "localhost:8248",
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
		"--" + anchorCredentialIssuerFlagName, "issuer.com",
		"--" + anchorCredentialURLFlagName, "peer.com",
		"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
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
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
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
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
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
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
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
				databaseTypeMemOption, ""))

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
					databaseTypeMongoDBOption, ""))

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

		startCmd.SetArgs(getTestArgs("https://ipfs.io", "local", "true", databaseTypeMemOption, ""))

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

	startCmd.SetArgs(getTestArgs("https://ipfs.io", "ipfs", "false", databaseTypeMemOption, ""))

	err := startCmd.Execute()
	require.EqualError(t, err, "CAS type cannot be set to IPFS if ipfs.io is being used as the node "+
		"since it doesn't support writes. Either switch the node URL to one that does support writes or "+
		"change the CAS type to local")
}

func TestStartCmdWithUnparsableIPFSURL(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(getTestArgs("%s", "ipfs", "false", databaseTypeMemOption, ""))

	err := startCmd.Execute()
	require.EqualError(t, err, `failed to parse IPFS URL: parse "%s": invalid URL escape "%s"`)
}

func TestStartCmdWithInvalidCASType(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(getTestArgs("localhost:8081", "InvalidName", "false", databaseTypeMemOption, ""))

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

		timeout, err := getDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.NoError(t, err)
		require.Equal(t, defaultIPFSTimeout, timeout)
	})

	t.Run("Invalid value -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "xxx")

		_, err := getDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Valid value -> success", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "30s")

		timeout, err := getDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
		require.NoError(t, err)
		require.Equal(t, 30*time.Second, timeout)
	})

	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, ipfsTimeoutEnvKey, "40s")
		defer restoreEnv()

		cmd := getTestCmd(t)

		timeout, err := getDuration(cmd, ipfsTimeoutFlagName, ipfsTimeoutEnvKey, defaultIPFSTimeout)
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

		defer func() {
			restoreURLEnv()
		}()

		cmd := getTestCmd(t)

		mqParams, err := getMQParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, u, mqParams.endpoint)
		require.Equal(t, mqDefaultObserverPoolSize, mqParams.observerPoolSize)
		require.Equal(t, mqDefaultOutboxPoolSize, mqParams.outboxPoolSize)
		require.Equal(t, mqDefaultInboxPoolSize, mqParams.inboxPoolSize)
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

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid publisher channel pool value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqPublisherChannelPoolSizeEnvKey, "xxx")

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid publisher confirm delivery -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqPublisherConfirmDeliveryEnvKey, "xxx")

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})
}

func TestGetOpQueueParameters(t *testing.T) {
	t.Run("Valid env values -> error", func(t *testing.T) {
		restorePoolEnv := setEnv(t, opQueuePoolEnvKey, "221")
		restoreTaskMonitorIntervalEnv := setEnv(t, opQueueTaskMonitorIntervalEnvKey, "17s")
		restoreTaskExpirationEnv := setEnv(t, opQueueTaskExpirationEnvKey, "33s")

		defer func() {
			restorePoolEnv()
			restoreTaskExpirationEnv()
			restoreTaskMonitorIntervalEnv()
		}()

		cmd := getTestCmd(t)

		opQueueParams, err := getOpQueueParameters(cmd, time.Minute,
			&mqParams{
				redeliveryMultiplier:      2.5,
				redeliveryInitialInterval: 4 * time.Second,
				maxRedeliveryInterval:     3 * time.Minute,
				maxRedeliveryAttempts:     23,
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
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		opQueueParams, err := getOpQueueParameters(cmd, time.Minute, &mqParams{})
		require.NoError(t, err)
		require.Equal(t, opQueueDefaultPoolSize, opQueueParams.PoolSize)
		require.Equal(t, opQueueDefaultTaskMonitorInterval, opQueueParams.TaskMonitorInterval)
		require.Equal(t, opQueueDefaultTaskExpiration, opQueueParams.TaskExpiration)
	})

	t.Run("Invalid pool size value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, opQueuePoolEnvKey, "xxx")

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, time.Minute, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid task monitor interval value -> error", func(t *testing.T) {
		restoreTaskMonitorIntervalEnv := setEnv(t, opQueueTaskMonitorIntervalEnvKey, "17")

		defer func() {
			restoreTaskMonitorIntervalEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, time.Minute, &mqParams{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid task expiration value -> error", func(t *testing.T) {
		restoreTaskExpirationEnv := setEnv(t, opQueueTaskExpirationEnvKey, "33")

		defer func() {
			restoreTaskExpirationEnv()
		}()

		cmd := getTestCmd(t)

		_, err := getOpQueueParameters(cmd, time.Minute, &mqParams{})
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

func setEnvVars(t *testing.T, databaseType, casType, replicateLocalCASToIPFS string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8237")
	require.NoError(t, err)

	err = os.Setenv(enableVCTFlagName, "true")
	require.NoError(t, err)

	err = os.Setenv(casTypeEnvKey, casType)
	require.NoError(t, err)

	err = os.Setenv(localCASReplicateInIPFSEnvKey, replicateLocalCASToIPFS)
	require.NoError(t, err)

	err = os.Setenv(batchWriterTimeoutEnvKey, "2000")
	require.NoError(t, err)

	err = os.Setenv(maxWitnessDelayEnvKey, "10m")
	require.NoError(t, err)

	err = os.Setenv(witnessStoreExpiryPeriodEnvKey, "12m")
	require.NoError(t, err)

	err = os.Setenv(signWithLocalWitnessEnvKey, "true")
	require.NoError(t, err)

	err = os.Setenv(didNamespaceEnvKey, "namespace")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseType)
	require.NoError(t, err)

	err = os.Setenv(kmsSecretsDatabaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialIssuerEnvKey, "issuer")
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialURLEnvKey, "peer")
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialDomainEnvKey, "domain")
	require.NoError(t, err)

	err = os.Setenv(enableUnpublishedOperationStoreEnvKey, "true")
	require.NoError(t, err)

	err = os.Setenv(sidetreeProtocolVersionsEnvKey, "1.0")
	require.NoError(t, err)

	err = os.Setenv(currentSidetreeProtocolVersionEnvKey, "1.0")
	require.NoError(t, err)

	err = os.Setenv(kmsTypeEnvKey, "local")
	require.NoError(t, err)

	err = os.Setenv(kmsSecretsDatabaseTypeFlagName, "mem")
	require.NoError(t, err)
}

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

	require.NoError(t, os.Setenv(name, value))

	return func() {
		require.NoError(t, os.Unsetenv(name))
	}
}

func getTestArgs(ipfsURL, casType, localCASReplicateInIPFSEnabled, databaseType, databaseURL string) []string {
	args := []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + hostMetricsURLFlagName, "localhost:8248",
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
		"--" + anchorCredentialIssuerFlagName, "issuer.com",
		"--" + anchorCredentialURLFlagName, "peer.com",
		"--" + LogLevelFlagName, log.ParseString(log.ERROR),
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
	}

	if databaseURL != "" {
		args = append(args, "--"+databaseURLFlagName, databaseURL, "--"+kmsSecretsDatabaseURLFlagName, databaseURL)
	}

	return args
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
