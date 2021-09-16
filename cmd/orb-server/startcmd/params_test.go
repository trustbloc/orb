/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
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
			"--" + casTypeFlagName, "", "--" + vctURLFlagName, "test",
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
			"local", "--" + vctURLFlagName, "test", "--" + didNamespaceFlagName, "",
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
			"local", "--" + vctURLFlagName, "test", "--" + didNamespaceFlagName,
			"namespace", "--" + databaseTypeFlagName, "",
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

	authDefs, err := getAuthTokenDefinitions(startCmd)
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

	authTokens, err := getAuthTokens(startCmd)
	require.NoError(t, err)
	require.Len(t, authTokens, 2)
	require.Equal(t, "ADMIN_TOKEN", authTokens["admin"])
	require.Equal(t, "READ_TOKEN", authTokens["read"])
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
			"localhost:8081", "--" + vctURLFlagName, "test",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither cas-type (command line flag) nor CAS_TYPE (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing anchor credential issuer arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchor-credential-issuer (command line flag) nor ANCHOR_CREDENTIAL_ISSUER (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing anchor credential domain arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchor-credential-domain (command line flag) nor ANCHOR_CREDENTIAL_DOMAIN (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing anchor credential url", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchor-credential-url (command line flag) nor ANCHOR_CREDENTIAL_URL (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing anchor credential signature suite arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchor-credential-signature-suite (command line flag) nor ANCHOR_CREDENTIAL_SIGNATURE_SUITE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid batch writer timeout", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + casTypeFlagName, "ipfs",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + batchWriterTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid max witness delay format")
	})

	t.Run("test invalid sign with local witness flag", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "5",
			"--" + signWithLocalWitnessFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + syncTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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

	t.Run("test invalid enable-did-discovery", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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

	t.Run("test invalid enable-create-document-store", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
			"--" + enableCreateDocumentStoreFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-create-document-store")
	})

	t.Run("test invalid enable-update-document-store", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
			"--" + enableUpdateDocumentStoreFlagName, "invalid bool",
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for enable-update-document-store")
	})

	t.Run("test invalid include-unpublished-operations-in-metadata", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + hostMetricsURLFlagName, "localhost:8248",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casTypeFlagName, "ipfs",
			"--" + ipfsURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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

	t.Run("Invalid max connection subscriptions", func(t *testing.T) {
		restoreEnv := setEnv(t, mqMaxConnectionSubscriptionsEnvKey, "xxx")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(getTestArgs("localhost:8081", "local", "false", databaseTypeMemOption, ""))

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value for mq-max-connection-subscription")
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

		err = os.Setenv(vctURLEnvKey, "localhost:8080")
		require.NoError(t, err)

		err = os.Setenv(casTypeEnvKey, "")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, os.Unsetenv(hostURLEnvKey))
			require.NoError(t, os.Unsetenv(vctURLEnvKey))
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
		"--" + vctURLFlagName, "localhost:8081",
		"--" + cidVersionFlagName, "-1",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "600",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
		"--" + anchorCredentialSignatureSuiteFlagName, "suite",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + kmsSecretsDatabaseURLFlagName, "badURL",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB")
	})

	t.Run("KMS fails (create kid)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + kmsStoreEndpointFlagName, "https://vct.example.com",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "create kid: init config value for")
	})

	t.Run("KMS fails (create remote store)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + kmsEndpointFlagName, "https://vct.example.com",
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
			err := startCmd.Execute()
			require.Nil(t, err)
			require.Equal(t, log.ERROR, log.GetLevel(""))
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
			err := startCmd.Execute()
			require.Nil(t, err)
			require.Equal(t, log.ERROR, log.GetLevel(""))
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
			err := startCmd.Execute()
			require.Nil(t, err)
			require.Equal(t, log.ERROR, log.GetLevel(""))
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

		timeout, err := getIPFSTimeout(cmd)
		require.NoError(t, err)
		require.Equal(t, defaultIPFSTimeout, timeout)
	})

	t.Run("Invalid value -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "xxx")

		_, err := getIPFSTimeout(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Valid value -> success", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+ipfsTimeoutFlagName, "30s")

		timeout, err := getIPFSTimeout(cmd)
		require.NoError(t, err)
		require.Equal(t, 30*time.Second, timeout)
	})

	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, ipfsTimeoutEnvKey, "40s")
		defer restoreEnv()

		cmd := getTestCmd(t)

		timeout, err := getIPFSTimeout(cmd)
		require.NoError(t, err)
		require.Equal(t, 40*time.Second, timeout)
	})
}

func TestGetMQParameters(t *testing.T) {
	const u = "amqp://admin:password@orb.mq.domain1.com:5672/"

	t.Run("Valid env values -> error", func(t *testing.T) {
		restoreURLEnv := setEnv(t, mqURLEnvKey, u)
		restoreOpPoolEnv := setEnv(t, mqOpPoolEnvKey, "221")
		restoreConnectionSubscriptionsEnv := setEnv(t, mqMaxConnectionSubscriptionsEnvKey, "456")

		defer func() {
			restoreURLEnv()
			restoreOpPoolEnv()
			restoreConnectionSubscriptionsEnv()
		}()

		cmd := getTestCmd(t)

		mqURL, poolSize, maxConnectionSubscriptions, err := getMQParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, u, mqURL)
		require.Equal(t, 221, poolSize)
		require.Equal(t, 456, maxConnectionSubscriptions)
	})

	t.Run("Not specified -> default value", func(t *testing.T) {
		restoreURLEnv := setEnv(t, mqURLEnvKey, u)

		defer func() {
			restoreURLEnv()
		}()

		cmd := getTestCmd(t)

		mqURL, poolSize, maxConnectionSubscriptions, err := getMQParameters(cmd)
		require.NoError(t, err)
		require.Equal(t, u, mqURL)
		require.Equal(t, 0, poolSize)
		require.Equal(t, mqDefaultMaxConnectionSubscriptions, maxConnectionSubscriptions)
	})

	t.Run("Invalid op pool size value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqOpPoolEnvKey, "xxx")

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, _, _, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Invalid max connection subscriptions value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, mqMaxConnectionSubscriptionsEnvKey, "xxx")

		defer func() {
			restoreEnv()
		}()

		cmd := getTestCmd(t)

		_, _, _, err := getMQParameters(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})
}

func TestCreateActivityPubStore(t *testing.T) {
	t.Run("Fail to create CouchDB provider", func(t *testing.T) {
		activityPubStore, err := createActivityPubStore(
			&orbParameters{dbParameters: &dbParameters{
				databaseType: databaseTypeCouchDBOption,
			}},
			"serviceEndpoint")
		require.EqualError(t, err, "failed to create CouchDB storage provider for ActivityPub: "+
			"failed to ping couchDB: url can't be blank")
		require.Nil(t, activityPubStore)
	})
	t.Run("Fail to create ActivityPub store using MongoDB", func(t *testing.T) {
		activityPubStore, err := createActivityPubStore(
			&orbParameters{dbParameters: &dbParameters{
				databaseType: databaseTypeMongoDBOption,
			}},
			"serviceEndpoint")
		require.EqualError(t, err, "create MongoDB storage provider for ActivityPub: failed to create "+
			`a new MongoDB client: error parsing uri: scheme must be "mongodb" or "mongodb+srv"`)
		require.Nil(t, activityPubStore)
	})
}

func setEnvVars(t *testing.T, databaseType, casType, replicateLocalCASToIPFS string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8237")
	require.NoError(t, err)

	err = os.Setenv(casTypeEnvKey, casType)
	require.NoError(t, err)

	err = os.Setenv(localCASReplicateInIPFSEnvKey, replicateLocalCASToIPFS)
	require.NoError(t, err)

	err = os.Setenv(batchWriterTimeoutEnvKey, "2000")
	require.NoError(t, err)

	err = os.Setenv(maxWitnessDelayEnvKey, "600")
	require.NoError(t, err)

	err = os.Setenv(signWithLocalWitnessEnvKey, "true")
	require.NoError(t, err)

	err = os.Setenv(didNamespaceEnvKey, "namespace")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseType)
	require.NoError(t, err)

	err = os.Setenv(kmsSecretsDatabaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialSignatureSuiteEnvKey, "suite")
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialIssuerEnvKey, "issuer")
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialURLEnvKey, "peer")
	require.NoError(t, err)

	err = os.Setenv(anchorCredentialDomainEnvKey, "domain")
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
		"--" + ipfsURLFlagName, ipfsURL,
		"--" + cidVersionFlagName, "0",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "600",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + casTypeFlagName, casType,
		"--" + didNamespaceFlagName, "namespace",
		"--" + databaseTypeFlagName, databaseType,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseType,
		"--" + anchorCredentialSignatureSuiteFlagName, "suite",
		"--" + anchorCredentialDomainFlagName, "domain.com",
		"--" + anchorCredentialIssuerFlagName, "issuer.com",
		"--" + anchorCredentialURLFlagName, "peer.com",
		"--" + LogLevelFlagName, log.ParseString(log.ERROR),
		"--" + localCASReplicateInIPFSFlagName, localCASReplicateInIPFSEnabled,
		"--" + enableUpdateDocumentStoreFlagName, "true",
		"--" + enableCreateDocumentStoreFlagName, "true",
		"--" + includePublishedOperationsFlagName, "true",
		"--" + includeUnpublishedOperationsFlagName, "true",
	}

	if databaseURL != "" {
		args = append(args, "--"+databaseURLFlagName, databaseURL, "--"+kmsSecretsDatabaseURLFlagName, databaseURL)
	}

	return args
}
