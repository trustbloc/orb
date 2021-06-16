/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestStartCmd(t *testing.T) {
	startCmd := GetStartCmd()

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start orb driver", startCmd.Short)
	require.Equal(t, "Start orb driver", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, "", hostURLFlagUsage)
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd()

	err := startCmd.Execute()
	require.Error(t, err)
	require.Equal(t,
		"Neither host-url (command line flag) nor ORB_DRIVER_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd()

	require.NoError(t, os.Setenv(hostURLEnvKey, "localhost:8080"))
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
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
