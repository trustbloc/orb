/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package deactivatedidcmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag = "--"

	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,A6CD57B60A99920E21D34C0C1E0D90D5

LaYVtZ4SsMthe6NjybSCQa4jOSOtCKEpO3wmbeSBYldJXXrDU4gOSVFiHJ45hTJP
Q7UGQKWNHeITH8NQlkmcySEKnaI9uyOkcb6TIvklapHCAF8cUf1kCHU10Eo0RTMI
2tJs7NW6oA4ZNi/o3xYVKVQ1R0lrgQGv9zatOupVPtQ=
-----END EC PRIVATE KEY-----
`
)

func TestMissingArg(t *testing.T) {
	t.Run("test did uri is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetDeactivateDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither did-uri (command line flag) nor "+
			"ORB_CLI_DID_URI (environment variable) have been set.")
	})
}

func TestKeyRetriever(t *testing.T) {
	kr := keyRetriever{signingKey: []byte("key")}

	_, err := kr.GetNextRecoveryPublicKey("", "")
	require.NoError(t, err)

	_, err = kr.GetNextUpdatePublicKey("", "")
	require.NoError(t, err)
}

func TestDeactivateDID(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer serv.Close()

	privateKeyfile, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = privateKeyfile.WriteString(privateKeyPEM)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(privateKeyfile.Name())) }()

	t.Run("test failed to deactivate did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetDeactivateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg(serv.URL)...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyfile.Name())...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to deactivate did")
	})

	t.Run("test failed to export public key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetDeactivateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg(serv.URL)...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, signingKeyIDFlagNameArg("id")...)
		args = append(args, kmsStoreEndpointFlagNameArg("kms")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "ExportPubKeyBytes key failed")
	})
}

func TestKeys(t *testing.T) {
	t.Run("test error getting signing key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetDeactivateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--signingkey) or key file (--signingkey-file) is required")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetDeactivateDIDCmd()

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

func sidetreeURLArg(value string) []string {
	return []string{flag + sidetreeURLOpsFlagName, value}
}

func signingKeyFileFlagNameArg(value string) []string {
	return []string{flag + signingKeyFileFlagName, value}
}

func signingKeyIDFlagNameArg(value string) []string {
	return []string{flag + signingKeyIDFlagName, value}
}

func kmsStoreEndpointFlagNameArg(value string) []string {
	return []string{flag + kmsStoreEndpointFlagName, value}
}

func signingKeyPasswordArg() []string {
	return []string{flag + signingKeyPasswordFlagName, "123"}
}
