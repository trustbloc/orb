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

	t.Run("test blank cas type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, "test", "--" + casTypeFlagName, "", "--" + vctURLFlagName, "test"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "cas-type value is empty", err.Error())
	})

	t.Run("test blank did namespace arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + casTypeFlagName,
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
			"--" + hostURLFlagName, "test", "--" + casTypeFlagName, "local", "--" + vctURLFlagName, "test",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, "",
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

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + vctURLFlagName, "test"}
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

	t.Run("Invalid ActivityPub page size", func(t *testing.T) {
		restoreEnv := setEnv(t, activityPubPageSizeEnvKey, "-125")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(defaultTestArgs())

		err := startCmd.Execute()

		require.EqualError(t, err, "activitypub-page-size: value must be greater than 0")
	})

	t.Run("Invalid NodeInfo refresh interval", func(t *testing.T) {
		restoreEnv := setEnv(t, nodeInfoRefreshIntervalEnvKey, "5")
		defer restoreEnv()

		startCmd := GetStartCmd()

		startCmd.SetArgs(defaultTestArgs())

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing unit in duration")
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
	startCmd := GetStartCmd()

	setEnvVars(t, databaseTypeMemOption)

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
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd()

	startCmd.SetArgs(defaultTestArgs())

	go func() {
		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	}()

	time.Sleep(50 * time.Millisecond)

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
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

func TestGetNodeInfoRefreshInterval(t *testing.T) {
	t.Run("Not specified -> default value", func(t *testing.T) {
		cmd := getTestCmd(t)

		interval, err := getNodeInfoRefreshInterval(cmd)
		require.NoError(t, err)
		require.Equal(t, defaultNodeInfoRefreshInterval, interval)
	})

	t.Run("Invalid value -> error", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+nodeInfoRefreshIntervalFlagName, "xxx")

		_, err := getNodeInfoRefreshInterval(cmd)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid value")
	})

	t.Run("Valid value -> success", func(t *testing.T) {
		cmd := getTestCmd(t, "--"+nodeInfoRefreshIntervalFlagName, "5s")

		interval, err := getNodeInfoRefreshInterval(cmd)
		require.NoError(t, err)
		require.Equal(t, 5*time.Second, interval)
	})

	t.Run("Valid env value -> error", func(t *testing.T) {
		restoreEnv := setEnv(t, nodeInfoRefreshIntervalEnvKey, "11s")
		defer restoreEnv()

		cmd := getTestCmd(t)

		interval, err := getNodeInfoRefreshInterval(cmd)
		require.NoError(t, err)
		require.Equal(t, 11*time.Second, interval)
	})
}

func setEnvVars(t *testing.T, databaseType string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8237")
	require.NoError(t, err)

	err = os.Setenv(casTypeEnvKey, "local")
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

func defaultTestArgs() []string {
	return []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + externalEndpointFlagName, "orb.example.com",
		"--" + discoveryDomainFlagName, "shared.example.com",
		"--" + ipfsURLFlagName, "localhost:8081",
		"--" + cidVersionFlagName, "0",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "600",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + casTypeFlagName, "local",
		"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
		"--" + anchorCredentialSignatureSuiteFlagName, "suite",
		"--" + anchorCredentialDomainFlagName, "domain.com",
		"--" + anchorCredentialIssuerFlagName, "issuer.com",
		"--" + anchorCredentialURLFlagName, "peer.com",
		"--" + LogLevelFlagName, log.ParseString(log.ERROR),
	}
}
