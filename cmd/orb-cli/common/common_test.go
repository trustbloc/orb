/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const (
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

	publicKeyData = `
[
 {
  "id": "key1",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication","assertionMethod","keyAgreement","capabilityDelegation","capabilityInvocation"],
  "jwkPath": "%s"
 },
 {
  "id": "key2",
  "type": "JwsVerificationKey2020",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 }
]`

	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,A6CD57B60A99920E21D34C0C1E0D90D5

LaYVtZ4SsMthe6NjybSCQa4jOSOtCKEpO3wmbeSBYldJXXrDU4gOSVFiHJ45hTJP
Q7UGQKWNHeITH8NQlkmcySEKnaI9uyOkcb6TIvklapHCAF8cUf1kCHU10Eo0RTMI
2tJs7NW6oA4ZNi/o3xYVKVQ1R0lrgQGv9zatOupVPtQ=
-----END EC PRIVATE KEY-----`

	pkPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

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

func TestParseKey(t *testing.T) {
	t.Run("test failed to parse private key", func(t *testing.T) {
		_, err := ParsePrivateKey([]byte("wrong"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse private key")
	})

	t.Run("test parse pkcs8 private key", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		b, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)

		_, err = ParsePrivateKey(b)
		require.NoError(t, err)
	})

	t.Run("test found unknown private key type in PKCS#8 wrapping", func(t *testing.T) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		b, err := x509.MarshalPKCS8PrivateKey(pk)
		require.NoError(t, err)

		_, err = ParsePrivateKey(b)
		require.Error(t, err)
		require.Contains(t, err.Error(), "found unknown private key type in PKCS#8 wrapping")
	})
}

func TestGetKey(t *testing.T) {
	t.Run("test key and file empty", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", ""))
		require.NoError(t, os.Setenv("key1_file", ""))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--key1) or key file (--key1-file) is required")
	})

	t.Run("test both key and file exist", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", "value"))
		require.NoError(t, os.Setenv("key1_file", "value"))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "only one of key (--key1) or key file (--key1-file) may be specified")
	})

	t.Run("test private key wrong pem", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", "wrong"))
		require.NoError(t, os.Setenv("key1_file", ""))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "private key not found in PEM")
	})

	t.Run("test private key file wrong path", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", ""))
		require.NoError(t, os.Setenv("key1_file", "./wrong"))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrong: no such file or directory")
	})

	t.Run("test private key file wrong path", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", ""))
		require.NoError(t, os.Setenv("key1_file", "./wrong"))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrong: no such file or directory")
	})

	t.Run("test public key wrong pem", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", "wrong"))
		require.NoError(t, os.Setenv("key1_file", ""))

		_, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", nil, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not found in PEM")
	})

	t.Run("test private key success", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv("key1", ""))
		require.NoError(t, os.Setenv("key1_file", file.Name()))

		k, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", []byte("123"), true)
		require.NoError(t, err)
		require.NotNil(t, k)
	})

	t.Run("test public key success", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		require.NoError(t, os.Setenv("key1", ""))
		require.NoError(t, os.Setenv("key1_file", file.Name()))

		k, err := GetKey(&cobra.Command{}, "key1", "key1", "key1-file",
			"key1_file", []byte("123"), false)
		require.NoError(t, err)
		require.NotNil(t, k)
	})
}

func TestGetServices(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		_, err := GetServices("./wrong")

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test services wrong path", func(t *testing.T) {
		_, err := GetServices("./wrong")

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test services wrong path", func(t *testing.T) {
		servicesFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = servicesFile.WriteString("wrong")
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

		_, err = GetServices(servicesFile.Name())

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("test success", func(t *testing.T) {
		servicesFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = servicesFile.WriteString(servicesData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

		services, err := GetServices(servicesFile.Name())

		require.NoError(t, err)
		require.Equal(t, 2, len(services))
	})
}

func TestGetVDRPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		_, err := GetVDRPublicKeysFromFile("./wrongfile")
		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrongfile: no such file or directory")
	})

	t.Run("test public key invalid jwk path", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(publicKeyData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		_, err = GetVDRPublicKeysFromFile(file.Name())

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read jwk file ")
	})

	t.Run("test public key success", func(t *testing.T) {
		jwk1File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk1File.WriteString(jwk1Data)
		require.NoError(t, err)

		jwk2File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk2File.WriteString(jwk2Data)
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(publicKeyData, jwk1File.Name(), jwk2File.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		didDoc, err := GetVDRPublicKeysFromFile(file.Name())
		require.NoError(t, err)
		require.Equal(t, len(didDoc.Authentication), 2)
	})
}
