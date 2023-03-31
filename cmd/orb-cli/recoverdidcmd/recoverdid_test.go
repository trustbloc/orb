/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package recoverdidcmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag          = "--"
	publickeyData = `
[
 {
  "id": "key1",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 },
 {
  "id": "key2",
  "type": "JsonWebKey2020",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 }
]`

	jwk1Data = `
{
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"o1bG1U7G3CNbtALMafUiFOq8ODraTyVTmPtRDO1QUWg",
  "y":""
}`
	jwk2Data = `
{
  "kty":"EC",
  "crv":"P-256",
  "x":"bGM9aNufpKNPxlkyacU1hGhQXm_aC8hIzSVeKDpwjBw",
  "y":"PfdmCOtIdVY2B6ucR4oQkt6evQddYhOyHoDYCaI2BJA"
}`

	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,A6CD57B60A99920E21D34C0C1E0D90D5

LaYVtZ4SsMthe6NjybSCQa4jOSOtCKEpO3wmbeSBYldJXXrDU4gOSVFiHJ45hTJP
Q7UGQKWNHeITH8NQlkmcySEKnaI9uyOkcb6TIvklapHCAF8cUf1kCHU10Eo0RTMI
2tJs7NW6oA4ZNi/o3xYVKVQ1R0lrgQGv9zatOupVPtQ=
-----END EC PRIVATE KEY-----
`

	pkPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

	servicesData = `[
  {
    "id": "svc1",
    "type": "type1",
    "priority": 1,
    "recipientKeys": ["key1"],
    "serviceEndpoint": [{
        "uri": "https://example.com",
        "routingKeys": ["key1"]
    }]
  },
  {
    "id": "svc2",
    "type": "type2",
    "priority": 2,
    "recipientKeys": ["key2"],
    "serviceEndpoint": [{
        "uri": "https://example.com",
        "routingKeys": ["key2"]
    }]
  }
]`
)

func TestMissingArg(t *testing.T) {
	t.Run("test did uri is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither did-uri (command line flag) nor "+
			"ORB_CLI_DID_URI (environment variable) have been set.")
	})
}

func TestRecoverDID(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer serv.Close()

	file, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(pkPEM)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	privateKeyfile, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = privateKeyfile.WriteString(privateKeyPEM)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(privateKeyfile.Name())) }()

	servicesFile, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = servicesFile.WriteString(servicesData)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

	jwk1File, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = jwk1File.WriteString(jwk1Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk1File.Name())) }()

	jwk2File, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = jwk2File.WriteString(jwk2Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk2File.Name())) }()

	publicKeyFile, err := os.CreateTemp("", "*.json")
	require.NoError(t, err)

	_, err = fmt.Fprintf(publicKeyFile, publickeyData, jwk1File.Name(), jwk2File.Name())
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

	t.Run("test failed to recover did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("wrongurl")...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, nextRecoveryKeyFileFlagNameArg(file.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(file.Name())...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyfile.Name())...)
		args = append(args, servicesFileArg(servicesFile.Name())...)
		args = append(args, publicKeyFileArg(publicKeyFile.Name())...)
		args = append(args, didAnchorOrigin()...)
		args = append(args, didAlsoKnownAsArg("https://blog.example")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to recover did")
	})

	t.Run("test failed to export public key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("wrongurl")...)
		args = append(args, nextUpdateKeyIDFlagNameArg("id")...)
		args = append(args, kmsStoreEndpointFlagNameArg("store")...)
		args = append(args, servicesFileArg(servicesFile.Name())...)
		args = append(args, publicKeyFileArg(publicKeyFile.Name())...)
		args = append(args, didAnchorOrigin()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "ExportPubKeyBytes key failed")
	})
}

func TestKeyRetriever(t *testing.T) {
	kr := keyRetriever{nextUpdateKey: []byte("key"), signingKey: []byte("key")}

	_, err := kr.GetNextRecoveryPublicKey("", "")
	require.NoError(t, err)

	_, err = kr.GetNextUpdatePublicKey("", "")
	require.NoError(t, err)
}

func TestKeys(t *testing.T) {
	t.Run("test error getting signing key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, didAnchorOrigin()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--signingkey) or key file (--signingkey-file) is required")
	})

	t.Run("test error getting next update key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		privateKeyfile, err := os.CreateTemp("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyfile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyfile.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyfile.Name())...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, didAnchorOrigin()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t,
			err.Error(), "either key (--nextupdatekey) or key file (--nextupdatekey-file) is required")
	})

	t.Run("test error getting next recovery key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		privateKeyfile, err := os.CreateTemp("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyfile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyfile.Name())) }()

		file, err := os.CreateTemp("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyfile.Name())...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, nextUpdateKeyFileFlagNameArg(file.Name())...)
		args = append(args, didAnchorOrigin()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t,
			err.Error(), "either key (--nextrecoverykey) or key file (--nextrecoverkey-file) is required")
	})
}

func TestService(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		file, err := os.CreateTemp("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		privateKeyfile, err := os.CreateTemp("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyfile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyfile.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, nextRecoveryKeyFileFlagNameArg(file.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(file.Name())...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyfile.Name())...)
		args = append(args, servicesFileArg("./wrong")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get services from file")
	})
}

func TestGetPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetRecoverDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg("./wrongfile")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to public key file")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetRecoverDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func didAnchorOrigin() []string {
	return []string{flag + didAnchorOriginFlagName, "origin"}
}

func publicKeyFileArg(value string) []string {
	return []string{flag + publicKeyFileFlagName, value}
}

func didURIArg() []string {
	return []string{flag + didURIFlagName, "did:ex:123"}
}

func servicesFileArg(value string) []string {
	return []string{flag + serviceFileFlagName, value}
}

func sidetreeURLArg(value string) []string {
	return []string{flag + sidetreeURLOpsFlagName, value}
}

func nextUpdateKeyFileFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyFileFlagName, value}
}

func nextUpdateKeyIDFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyIDFlagName, value}
}

func nextRecoveryKeyFileFlagNameArg(value string) []string {
	return []string{flag + nextRecoveryKeyFileFlagName, value}
}

func signingKeyFileFlagNameArg(value string) []string {
	return []string{flag + signingKeyFileFlagName, value}
}

func signingKeyPasswordArg() []string {
	return []string{flag + signingKeyPasswordFlagName, "123"}
}

func kmsStoreEndpointFlagNameArg(value string) []string {
	return []string{flag + kmsStoreEndpointFlagName, value}
}

func didAlsoKnownAsArg(value string) []string {
	return []string{flag + didAlsoKnownAsFlagName, value}
}
