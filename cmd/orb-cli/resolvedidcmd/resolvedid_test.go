/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package resolvedidcmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag = "--"
)

func TestMissingArg(t *testing.T) {
	t.Run("test did uri is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetResolveDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither did-uri (command line flag) nor "+
			"ORB_CLI_DID_URI (environment variable) have been set.")
	})

	t.Run("test verify type is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetResolveDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, didURIArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither verify-resolution-result-type (command line flag) nor "+
			"ORB_CLI_VERIFY_RESOLUTION_RESULT_TYPE (environment variable) have been set.")
	})

	t.Run("test wrong value for verify type", func(t *testing.T) {
		os.Clearenv()
		cmd := GetResolveDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, didURIArg()...)
		args = append(args, verifyTypeArg("wrong")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported wrong for verifyResolutionResultType")
	})
}

func TestResolveDID(t *testing.T) {
	t.Run("test failed to resolve did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetResolveDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, didURIArg()...)
		args = append(args, verifyTypeArg("none")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve did")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetResolveDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func didURIArg() []string {
	return []string{flag + didURIFlagName, "did:ex:123"}
}

func verifyTypeArg(value string) []string {
	return []string{flag + verifyTypeFlagName, value}
}
