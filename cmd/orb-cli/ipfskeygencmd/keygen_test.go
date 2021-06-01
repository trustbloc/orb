/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipfskeygencmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag = "--"
)

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))
	defer os.Clearenv()

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing ipfs url arg", func(t *testing.T) {
		startCmd := GetCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither ipfs-url (command line flag) nor ORB_CLI_IPFS_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing key name arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, ipfsURL("localhost:8080")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither key-name (command line flag) nor ORB_CLI_KEY_NAME (environment variable) have been set.",
			err.Error())
	})
}

func TestGenerateKey(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("test failed to create did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL("wrongurl")...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send http request")
	})

	t.Run("success", func(t *testing.T) {
		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL(serv.URL)...)
		args = append(args, keyName("k1")...)
		args = append(args, keyDir(os.TempDir())...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}

func ipfsURL(value string) []string {
	return []string{flag + ipfsURLFlagName, value}
}

func keyName(value string) []string {
	return []string{flag + keyNameFlagName, value}
}

func keyDir(value string) []string {
	return []string{flag + keyDirFlagName, value}
}
