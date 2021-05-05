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

	t.Run("test blank cas url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, "test"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)

		const errMsg = "vct-url (command line flag) nor ORB_VCT_URL (environment variable) have been set."
		require.Contains(t, err.Error(), errMsg)
	})

	t.Run("test blank cas url arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{"--" + hostURLFlagName, "test", "--" + casURLFlagName, "", "--" + vctURLFlagName, "test"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "cas-url value is empty", err.Error())
	})

	t.Run("test blank did namespace arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + casURLFlagName,
			"test", "--" + vctURLFlagName, "test", "--" + didNamespaceFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "did-namespace value is empty", err.Error())
	})

	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "test", "--" + casURLFlagName, "test", "--" + vctURLFlagName, "test",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "database-type value is empty", err.Error())
	})
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
			"Neither cas-url (command line flag) nor CAS_URL (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing anchor credential issuer arg", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casURLFlagName, "localhost:8081",
			"--" + batchWriterTimeoutFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
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
			"--" + casURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
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
			"--" + casURLFlagName, "localhost:8081",
			"--" + maxWitnessDelayFlagName, "5",
			"--" + signWithLocalWitnessFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
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

	t.Run("test invalid startup delay format", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casURLFlagName, "localhost:8081",
			"--" + startupDelayFlagName, "abc",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + LogLevelFlagName, log.ParseString(log.ERROR),
		}

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid start-up delay format")
	})
	t.Run("test invalid enable-http-signatures", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8247",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + externalEndpointFlagName, "orb.example.com",
			"--" + casURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
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

		err = os.Setenv(casURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "CAS_URL value is empty", err.Error())
	})
}

func TestStartCmdCreateKMSFailure(t *testing.T) {
	t.Run("KMS fails (DB)", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + casURLFlagName, "localhost:8081",
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
			"--" + casURLFlagName, "localhost:8081",
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
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 3)))
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd()

	args := []string{
		"--" + hostURLFlagName, "localhost:8247",
		"--" + externalEndpointFlagName, "orb.example.com",
		"--" + casURLFlagName, "localhost:8081",
		"--" + batchWriterTimeoutFlagName, "700",
		"--" + maxWitnessDelayFlagName, "600",
		"--" + signWithLocalWitnessFlagName, "false",
		"--" + startupDelayFlagName, "1",
		"--" + didNamespaceFlagName, "namespace", "--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
		"--" + anchorCredentialSignatureSuiteFlagName, "suite",
		"--" + anchorCredentialDomainFlagName, "domain.com",
		"--" + anchorCredentialIssuerFlagName, "issuer.com",
		"--" + anchorCredentialURLFlagName, "peer.com",
		"--" + LogLevelFlagName, log.ParseString(log.ERROR),
	}
	startCmd.SetArgs(args)

	go func() {
		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	}()

	time.Sleep(50 * time.Millisecond)

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGINT))
}

func setEnvVars(t *testing.T, databaseType string) {
	err := os.Setenv(hostURLEnvKey, "localhost:8237")
	require.NoError(t, err)

	err = os.Setenv(vctURLEnvKey, "localhost:8237")
	require.NoError(t, err)

	err = os.Setenv(casURLEnvKey, "cas")
	require.NoError(t, err)

	err = os.Setenv(batchWriterTimeoutEnvKey, "2000")
	require.NoError(t, err)

	err = os.Setenv(maxWitnessDelayEnvKey, "600")
	require.NoError(t, err)

	err = os.Setenv(signWithLocalWitnessEnvKey, "true")
	require.NoError(t, err)

	err = os.Setenv(startupDelayEnvKey, "1")
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
	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsSecretsDatabasePrefixEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
