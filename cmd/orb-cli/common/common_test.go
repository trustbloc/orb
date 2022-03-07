/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
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
  "type": "JsonWebKey2020",
  "purposes": ["authentication"],
  "jwkPath": "%s"
 },
 {
  "id": "key3",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["assertionMethod"],
  "b58Key": "36d8RkFy2SdabnGzcZ3LcCSDA8NP5T4bsoADwuXtoN3B"
 }
]`

	publicKeyDataWithJWKAndB58 = `
[
 {
  "id": "key1",
  "type": "Ed25519VerificationKey2018",
  "purposes": ["authentication","assertionMethod","keyAgreement","capabilityDelegation","capabilityInvocation"],
  "jwkPath": "%s",
  "b58Key": "36d8RkFy2SdabnGzcZ3LcCSDA8NP5T4bsoADwuXtoN3B"
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

func TestSendRequest(t *testing.T) {
	t.Run("test error 500", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		_, err := SendRequest(&http.Client{}, nil, map[string]string{"k1": "v1"}, http.MethodGet, serv.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
	})
}

func TestSigner(t *testing.T) {
	t.Run("test ed25519 key", func(t *testing.T) {
		pk, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		s := NewSigner(privateKey, "", nil, pk)

		h := s.Headers()
		require.NotNil(t, h)

		pkJWK := s.PublicKeyJWK()
		require.NotNil(t, pkJWK)

		_, err = s.Sign([]byte("data"))
		require.NoError(t, err)
	})

	t.Run("test ec key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		s := NewSigner(key, "", nil, key.PublicKey)

		h := s.Headers()
		require.NotNil(t, h)

		pkJWK := s.PublicKeyJWK()
		require.NotNil(t, pkJWK)

		_, err = s.Sign([]byte("data"))
		require.NoError(t, err)
	})
}

func TestGetPublicKeyFromKMS(t *testing.T) {
	t.Run("test key empty", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", ""))

		_, err := GetPublicKeyFromKMS(&cobra.Command{}, "key1", "key1", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "key1 value is empty")
	})

	t.Run("test error export public key", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", "value"))

		_, err := GetPublicKeyFromKMS(&cobra.Command{}, "key1", "key1",
			&mockkms.KeyManager{ExportPubKeyBytesErr: fmt.Errorf("failed to export")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to export")
	})

	t.Run("test success", func(t *testing.T) {
		os.Clearenv()

		require.NoError(t, os.Setenv("key1", "value"))

		_, err := GetPublicKeyFromKMS(&cobra.Command{}, "key1", "key1",
			&mockkms.KeyManager{ExportPubKeyBytesValue: []byte(pkPEM)})
		require.NoError(t, err)
	})
}

func TestSendHTTPRequest(t *testing.T) {
	t.Run("test error 500", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		cmd := newMockCmd(func(cmd *cobra.Command, args []string) error {
			_, err := SendHTTPRequest(cmd, nil, http.MethodGet, serv.URL)

			return err
		})

		cmd.SetArgs([]string{"--" + AuthTokenFlagName, "ADMIN_TOKEN"})

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response from")
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

	t.Run("test public key unmarshal error", func(t *testing.T) {
		jwk1File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk1File.WriteString("oops")
		require.NoError(t, err)

		jwk2File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk2File.WriteString("oops again")
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(publicKeyData, jwk1File.Name(), jwk2File.Name()))
		require.NoError(t, err)

		defer func() {
			require.NoError(t, os.Remove(file.Name()))
			require.NoError(t, os.Remove(jwk1File.Name()))
			require.NoError(t, os.Remove(jwk2File.Name()))
		}()

		didDoc, err := GetVDRPublicKeysFromFile(file.Name())
		require.Error(t, err)
		require.Nil(t, didDoc)

		require.Contains(t, err.Error(), "failed to unmarshal to jwk")
	})

	t.Run("test public key multiple key material fields", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(publicKeyDataWithJWKAndB58)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		_, err = GetVDRPublicKeysFromFile(file.Name())

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key needs exactly one of jwkPath and b58Key")
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

		defer func() {
			require.NoError(t, os.Remove(file.Name()))
			require.NoError(t, os.Remove(jwk1File.Name()))
			require.NoError(t, os.Remove(jwk2File.Name()))
		}()

		didDoc, err := GetVDRPublicKeysFromFile(file.Name())
		require.NoError(t, err)
		require.Equal(t, len(didDoc.Authentication), 2)
	})
}

func newMockCmd(runFUnc func(cmd *cobra.Command, args []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "mock",
		RunE: runFUnc,
	}

	AddCommonFlags(cmd)

	return cmd
}
