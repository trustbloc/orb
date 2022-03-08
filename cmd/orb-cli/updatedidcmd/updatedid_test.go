/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updatedidcmd

import (
	"fmt"
	"io/ioutil"
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

	pkPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,A6CD57B60A99920E21D34C0C1E0D90D5

LaYVtZ4SsMthe6NjybSCQa4jOSOtCKEpO3wmbeSBYldJXXrDU4gOSVFiHJ45hTJP
Q7UGQKWNHeITH8NQlkmcySEKnaI9uyOkcb6TIvklapHCAF8cUf1kCHU10Eo0RTMI
2tJs7NW6oA4ZNi/o3xYVKVQ1R0lrgQGv9zatOupVPtQ=
-----END EC PRIVATE KEY-----
`

	servicesData = `[
  {
    "id": "svc1",
    "type": "type1",
    "priority": 1,
    "routingKeys": ["key1"],
    "recipientKeys": ["key1"],
    "serviceEndpoint": "http://www.example.com"
  },
  {
    "id": "svc2",
    "type": "type2",
    "priority": 2,
    "routingKeys": ["key2"],
    "recipientKeys": ["key2"],
    "serviceEndpoint": "http://www.example.com"
  }
]`
)

func TestMissingArg(t *testing.T) {
	t.Run("test did uri is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

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
	kr := keyRetriever{nextUpdateKey: []byte("key"), signingKey: []byte("key")}

	_, err := kr.GetNextRecoveryPublicKey("", "")
	require.NoError(t, err)

	_, err = kr.GetNextUpdatePublicKey("", "")
	require.NoError(t, err)
}

func TestKeys(t *testing.T) {
	t.Run("test signing key empty", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("url")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--signingkey) or key file (--signingkey-file) is required")
	})

	t.Run("test next update key wrong pem", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, signingKeyFileFlagNameArg(file.Name())...)
		args = append(args, nextUpdateKeyFlagNameArg("w")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not found in PEM")
	})
}

func TestService(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		privateKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyFile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyFile.Name())) }()

		publicKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = publicKeyFile.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyFile.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(publicKeyFile.Name())...)
		args = append(args, addServicesFileArg("./wrong")...)
		args = append(args, signingKeyPasswordArg()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})
}

func TestUpdateDID(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{}")
	}))
	defer serv.Close()

	privateKeyFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = privateKeyFile.WriteString(privateKeyPEM)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(privateKeyFile.Name())) }()

	publicKeyFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = publicKeyFile.WriteString(pkPEM)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

	servicesFile, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = servicesFile.WriteString(servicesData)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

	jwk1File, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = jwk1File.WriteString(jwk1Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk1File.Name())) }()

	jwk2File, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = jwk2File.WriteString(jwk2Data)
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(jwk2File.Name())) }()

	file, err := ioutil.TempFile("", "*.json")
	require.NoError(t, err)

	_, err = file.WriteString(fmt.Sprintf(publickeyData, jwk1File.Name(), jwk2File.Name()))
	require.NoError(t, err)

	defer func() { require.NoError(t, os.Remove(file.Name())) }()

	t.Run("test failed to update did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("wrongurl")...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyFile.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(publicKeyFile.Name())...)
		args = append(args, addServicesFileArg(servicesFile.Name())...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, addPublicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to update did")
	})

	t.Run("test failed to export public key", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("wrongurl")...)
		args = append(args, nextUpdateKeyIDFlagNameArg("id")...)
		args = append(args, kmsStoreEndpointFlagNameArg("store")...)
		args = append(args, addServicesFileArg(servicesFile.Name())...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, addPublicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "ExportPubKeyBytes key failed")
	})
}

func TestGetPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, addPublicKeyFileArg("./wrongfile")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrongfile: no such file or directory")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetUpdateDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func signingKeyPasswordArg() []string {
	return []string{flag + signingKeyPasswordFlagName, "123"}
}

func sidetreeURLArg(value string) []string {
	return []string{flag + sidetreeURLOpsFlagName, value}
}

func didURIArg() []string {
	return []string{flag + didURIFlagName, "did:ex:123"}
}

func addPublicKeyFileArg(value string) []string {
	return []string{flag + addPublicKeyFileFlagName, value}
}

func signingKeyFileFlagNameArg(value string) []string {
	return []string{flag + signingKeyFileFlagName, value}
}

func nextUpdateKeyFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyFlagName, value}
}

func nextUpdateKeyIDFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyIDFlagName, value}
}

func nextUpdateKeyFileFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyFileFlagName, value}
}

func addServicesFileArg(value string) []string {
	return []string{flag + addServiceFileFlagName, value}
}

func kmsStoreEndpointFlagNameArg(value string) []string {
	return []string{flag + kmsStoreEndpointFlagName, value}
}
