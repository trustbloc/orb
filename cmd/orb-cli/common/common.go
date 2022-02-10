/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jwk2 "github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
)

var logger = log.New("orb-cli")

const (
	// TLSSystemCertPoolFlagName defines the flag for the system certificate pool.
	TLSSystemCertPoolFlagName = "tls-systemcertpool"
	// TLSSystemCertPoolFlagUsage defines the usage of the system certificate pool flag.
	TLSSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + TLSSystemCertPoolEnvKey
	// TLSSystemCertPoolEnvKey defines the environment variable for the system certificate pool flag.
	TLSSystemCertPoolEnvKey = "ORB_CLI_TLS_SYSTEMCERTPOOL"

	// TLSCACertsFlagName defines the flag for the CA certs flag.
	TLSCACertsFlagName = "tls-cacerts"
	// TLSCACertsFlagUsage defines the usage of the CA certs flag.
	TLSCACertsFlagUsage = "Comma-separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + TLSCACertsEnvKey
	// TLSCACertsEnvKey defines the environment variable for the CA certs flag.
	TLSCACertsEnvKey = "ORB_CLI_TLS_CACERTS"

	// AuthTokenFlagName defines the flag for the authorization bearer token.
	AuthTokenFlagName = "auth-token"
	// AuthTokenFlagUsage defines the usage of the authorization bearer token flag.
	AuthTokenFlagUsage = "Auth token." +
		" Alternatively, this can be set with the following environment variable: " + AuthTokenEnvKey
	// AuthTokenEnvKey defines the environment variable for the authorization bearer token flag.
	AuthTokenEnvKey = "ORB_CLI_AUTH_TOKEN" //nolint:gosec
)

// PublicKey struct.
type PublicKey struct {
	ID       string   `json:"id,omitempty"`
	Type     string   `json:"type,omitempty"`
	Purposes []string `json:"purposes,omitempty"`
	JWKPath  string   `json:"jwkPath,omitempty"`
	B58Key   string   `json:"b58Key,omitempty"`
}

// PublicKeyFromFile public key from file.
func PublicKeyFromFile(file string) (crypto.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}

	return PublicKeyFromPEM(keyBytes)
}

// PublicKeyFromPEM public key from pem.
func PublicKeyFromPEM(pubKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("public key not found in PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	return publicKey, nil
}

// PrivateKeyFromFile private key from file.
func PrivateKeyFromFile(file string, password []byte) (crypto.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}

	return PrivateKeyFromPEM(keyBytes, password)
}

// PrivateKeyFromPEM private key pem.
func PrivateKeyFromPEM(privateKeyPEM, password []byte) (crypto.PrivateKey, error) {
	privBlock, _ := pem.Decode(privateKeyPEM)
	if privBlock == nil {
		return nil, fmt.Errorf("private key not found in PEM")
	}

	b := privBlock.Bytes

	if len(password) != 0 {
		var err error
		// FIXME: x509.DecryptPEMBlock deprecated in go1.16 due to security flaws.
		//   this should be replaced by a different infrastructure for configuring keys before this goes into prod.
		b, err = x509.DecryptPEMBlock(privBlock, password) //nolint:staticcheck

		if err != nil {
			return nil, err
		}
	}

	privKey, err := ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// ParsePrivateKey parse private key.
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case ed25519.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// GetKey get key.
func GetKey(cmd *cobra.Command, keyFlagName, keyEnvKey, keyFileFlagName, keyFileEnvKey string,
	password []byte, privateKey bool) (interface{}, error) {
	keyString := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFlagName,
		keyEnvKey)

	keyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFileFlagName,
		keyFileEnvKey)

	if keyString == "" && keyFile == "" {
		return nil, fmt.Errorf("either key (--%s) or key file (--%s) is required", keyFlagName, keyFileFlagName)
	}

	if keyString != "" && keyFile != "" {
		return nil, fmt.Errorf("only one of key (--%s) or key file (--%s) may be specified", keyFlagName, keyFileFlagName)
	}

	if privateKey {
		if keyFile != "" {
			return PrivateKeyFromFile(keyFile, password)
		}

		return PrivateKeyFromPEM([]byte(keyString), password)
	}

	if keyFile != "" {
		return PublicKeyFromFile(keyFile)
	}

	return PublicKeyFromPEM([]byte(keyString))
}

// GetVDRPublicKeysFromFile get public keys from file.
func GetVDRPublicKeysFromFile(publicKeyFilePath string) (*docdid.Doc, error) { //nolint:gocyclo,cyclop,funlen
	pkData, err := ioutil.ReadFile(filepath.Clean(publicKeyFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to public key file '%s' : %w", publicKeyFilePath, err)
	}

	var publicKeys []PublicKey
	if err := json.Unmarshal(pkData, &publicKeys); err != nil {
		return nil, err
	}

	didDoc := &docdid.Doc{}

	for _, v := range publicKeys {
		if (v.JWKPath == "") == (v.B58Key == "") {
			return nil, fmt.Errorf("public key needs exactly one of jwkPath and b58Key")
		}

		var vm *docdid.VerificationMethod

		if v.JWKPath != "" {
			jwkData, err := ioutil.ReadFile(filepath.Clean(v.JWKPath))
			if err != nil {
				return nil, fmt.Errorf("failed to read jwk file '%s' : %w", v.JWKPath, err)
			}

			var jwk jwk2.JWK
			if errUnmarshal := jwk.UnmarshalJSON(jwkData); errUnmarshal != nil {
				return nil, fmt.Errorf("failed to unmarshal to jwk: %w", errUnmarshal)
			}

			vm, err = docdid.NewVerificationMethodFromJWK(v.ID, v.Type, "", &jwk)
			if err != nil {
				return nil, err
			}
		} else if v.B58Key != "" {
			vm = docdid.NewVerificationMethodFromBytes(v.ID, v.Type, "", base58.Decode(v.B58Key))
		}

		for _, p := range v.Purposes {
			switch p {
			case doc.KeyPurposeAuthentication:
				didDoc.Authentication = append(didDoc.Authentication,
					*docdid.NewReferencedVerification(vm, docdid.Authentication))
			case doc.KeyPurposeAssertionMethod:
				didDoc.AssertionMethod = append(didDoc.AssertionMethod,
					*docdid.NewReferencedVerification(vm, docdid.AssertionMethod))
			case doc.KeyPurposeKeyAgreement:
				didDoc.KeyAgreement = append(didDoc.KeyAgreement,
					*docdid.NewReferencedVerification(vm, docdid.KeyAgreement))
			case doc.KeyPurposeCapabilityDelegation:
				didDoc.CapabilityInvocation = append(didDoc.CapabilityInvocation,
					*docdid.NewReferencedVerification(vm, docdid.CapabilityDelegation))
			case doc.KeyPurposeCapabilityInvocation:
				didDoc.CapabilityDelegation = append(didDoc.CapabilityDelegation,
					*docdid.NewReferencedVerification(vm, docdid.CapabilityInvocation))
			default:
				return nil, fmt.Errorf("public key purpose %s not supported", p)
			}
		}
	}

	return didDoc, nil
}

// GetServices get services.
func GetServices(serviceFilePath string) ([]docdid.Service, error) {
	svcData, err := ioutil.ReadFile(filepath.Clean(serviceFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to service file '%s' : %w", serviceFilePath, err)
	}

	var services []docdid.Service
	if err := json.Unmarshal(svcData, &services); err != nil {
		return nil, err
	}

	return services, nil
}

// SendRequest send http request.
func SendRequest(httpClient *http.Client, req []byte, headers map[string]string, method,
	endpointURL string) ([]byte, error) {
	var httpReq *http.Request

	var err error

	if len(req) == 0 {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	} else {
		httpReq, err = http.NewRequestWithContext(context.Background(),
			method, endpointURL, bytes.NewBuffer(req))
		if err != nil {
			return nil, fmt.Errorf("failed to create http request: %w", err)
		}
	}

	for k, v := range headers {
		httpReq.Header.Add(k, v)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

// SendHTTPRequest sends the given HTTP request using the options provided on the command-line.
func SendHTTPRequest(cmd *cobra.Command, reqBytes []byte, method, endpointURL string) ([]byte, error) {
	client, err := newHTTPClient(cmd)
	if err != nil {
		return nil, err
	}

	return SendRequest(client, reqBytes, newAuthTokenHeader(cmd), method, endpointURL)
}

func closeResponseBody(respBody io.Closer) {
	if err := respBody.Close(); err != nil {
		logger.Errorf("Failed to close response body: %v", err)
	}
}

func newHTTPClient(cmd *cobra.Command) (*http.Client, error) {
	rootCAs, err := getRootCAs(cmd)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs:    rootCAs,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, TLSSystemCertPoolFlagName,
		TLSSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, TLSCACertsFlagName,
		TLSCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func newAuthTokenHeader(cmd *cobra.Command) map[string]string {
	headers := make(map[string]string)

	authToken := cmdutils.GetUserSetOptionalVarFromString(cmd, AuthTokenFlagName, AuthTokenEnvKey)
	if authToken != "" {
		headers["Authorization"] = "Bearer " + authToken
	}

	return headers
}

// GetDuration get duration.
func GetDuration(cmd *cobra.Command, flagName, envKey string,
	defaultDuration time.Duration) (time.Duration, error) {
	timeoutStr, err := cmdutils.GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return -1, err
	}

	if timeoutStr == "" {
		return defaultDuration, nil
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return -1, fmt.Errorf("invalid value [%s]: %w", timeoutStr, err)
	}

	return timeout, nil
}

// AddCommonFlags adds common flags to the given command.
func AddCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP(TLSSystemCertPoolFlagName, "", "", TLSSystemCertPoolFlagUsage)
	cmd.Flags().StringArrayP(TLSCACertsFlagName, "", nil, TLSCACertsFlagUsage)
	cmd.Flags().StringP(AuthTokenFlagName, "", "", AuthTokenFlagUsage)
}
