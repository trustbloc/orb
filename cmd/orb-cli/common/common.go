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
	"crypto/elliptic"
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
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	jwk2 "github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/client"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
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

	// TargetOverrideFlagName defines the flag for specifying target overrides.
	TargetOverrideFlagName = "target-override"
	// TargetOverrideFlagUsage defines the flag for target override usage.
	TargetOverrideFlagUsage = "Overrides one or more targets used for resolving HTTP endpoints. " +
		" For example, --target-override orb.domain2.com->localhost:48426 will use localhost:48426 instead of" +
		" orb.domain2.com for HTTP requests. This flag should only be used for testing." +
		" Alternatively, this can be set with the following environment variable: " + TargetOverrideEnvKey
	// TargetOverrideEnvKey defines the flag for target override environment variable.
	TargetOverrideEnvKey = "ORB_CLI_OUTBOX_URL"
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

// GetPublicKeyFromKMS get publickey from kms.
func GetPublicKeyFromKMS(cmd *cobra.Command, keyIDFlagName, keyIDEnvKey string,
	webKmsClient kms.KeyManager) (interface{}, error) {
	keyID, err := cmdutil.GetUserSetVarFromString(cmd, keyIDFlagName,
		keyIDEnvKey, false)
	if err != nil {
		return nil, err
	}

	keyBytes, kt, err := webKmsClient.ExportPubKeyBytes(keyID)
	if err != nil {
		return nil, err
	}

	switch kt { // nolint:exhaustive // default catch-all
	case kms.ECDSAP256DER, kms.ECDSAP384DER, kms.ECDSAP521DER:
		pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ecdsa key in DER format: %w", err)
		}

		return pubKey, nil
	case kms.ECDSAP256IEEEP1363, kms.ECDSAP384IEEEP1363, kms.ECDSAP521IEEEP1363:
		curves := map[kms.KeyType]elliptic.Curve{
			kms.ECDSAP256IEEEP1363: elliptic.P256(),
			kms.ECDSAP384IEEEP1363: elliptic.P384(),
			kms.ECDSAP521IEEEP1363: elliptic.P521(),
		}
		crv := curves[kt]
		x, y := elliptic.Unmarshal(crv, keyBytes)

		return &ecdsa.PublicKey{
			Curve: crv,
			X:     x,
			Y:     y,
		}, nil
	case kms.ED25519:
		return ed25519.PublicKey(keyBytes), nil
	}

	return nil, fmt.Errorf("                                                                               : %s", kt)
}

// GetKey get key.
func GetKey(cmd *cobra.Command, keyFlagName, keyEnvKey, keyFileFlagName, keyFileEnvKey string,
	password []byte, privateKey bool) (interface{}, error) {
	keyString := cmdutil.GetUserSetOptionalVarFromString(cmd, keyFlagName,
		keyEnvKey)

	keyFile := cmdutil.GetUserSetOptionalVarFromString(cmd, keyFileFlagName,
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
	c, err := NewHTTPClient(cmd)
	if err != nil {
		return nil, err
	}

	return SendRequest(c, reqBytes, newAuthTokenHeader(cmd), method, endpointURL)
}

func closeResponseBody(respBody io.Closer) {
	if err := respBody.Close(); err != nil {
		logger.Errorf("Failed to close response body: %v", err)
	}
}

// NewHTTPClient returns a new HTTP client using the arguments from the given command.
func NewHTTPClient(cmd *cobra.Command) (*http.Client, error) {
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
	tlsSystemCertPoolString := cmdutil.GetUserSetOptionalVarFromString(cmd, TLSSystemCertPoolFlagName,
		TLSSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, TLSCACertsFlagName,
		TLSCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func newAuthTokenHeader(cmd *cobra.Command) map[string]string {
	headers := make(map[string]string)

	authToken := cmdutil.GetUserSetOptionalVarFromString(cmd, AuthTokenFlagName, AuthTokenEnvKey)
	if authToken != "" {
		headers["Authorization"] = "Bearer " + authToken
	}

	return headers
}

// GetDuration get duration.
func GetDuration(cmd *cobra.Command, flagName, envKey string,
	defaultDuration time.Duration) (time.Duration, error) {
	timeoutStr, err := cmdutil.GetUserSetVarFromString(cmd, flagName, envKey, true)
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
	cmd.Flags().StringArrayP(TargetOverrideFlagName, "", nil, TargetOverrideFlagUsage)
}

// Signer operation.
type Signer struct {
	signer             client.Signer
	signingKeyID       string
	publicKey          *jws.JWK
	webKmsCryptoClient webcrypto.Crypto
}

// nolint: gochecknoglobals
var headerAlgorithm = map[string]string{
	"Ed25519": "EdDSA",
	"P-256":   "ES256",
	"P-384":   "ES384",
	"P-521":   "ES521",
}

// NewSigner return new signer.
func NewSigner(signingkey crypto.PrivateKey, signingKeyID string, webKmsCryptoClient webcrypto.Crypto,
	signingKeyPK crypto.PublicKey) *Signer {
	if webKmsCryptoClient == nil {
		switch key := signingkey.(type) {
		case *ecdsa.PrivateKey:
			publicKey, err := pubkey.GetPublicKeyJWK(key.Public())
			if err != nil {
				panic(err.Error())
			}

			return &Signer{signer: ecsigner.New(key, "ES256", uuid.NewString()), publicKey: publicKey}
		case ed25519.PrivateKey:
			publicKey, err := pubkey.GetPublicKeyJWK(key.Public())
			if err != nil {
				panic(err.Error())
			}

			return &Signer{signer: edsigner.New(key, "EdDSA", uuid.NewString()), publicKey: publicKey}
		}
	}

	publicKey, err := pubkey.GetPublicKeyJWK(signingKeyPK)
	if err != nil {
		panic(err.Error())
	}

	return &Signer{signingKeyID: signingKeyID, webKmsCryptoClient: webKmsCryptoClient, publicKey: publicKey}
}

// Sign data.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	if s.webKmsCryptoClient == nil {
		return s.signer.Sign(data)
	}

	return s.webKmsCryptoClient.Sign(data, s.signingKeyID)
}

// Headers return headers.
func (s *Signer) Headers() jws.Headers {
	if s.webKmsCryptoClient == nil {
		return s.signer.Headers()
	}

	headers := make(jws.Headers)

	headers[jws.HeaderKeyID] = uuid.NewString()
	headers[jws.HeaderAlgorithm] = headerAlgorithm[s.publicKey.Crv]

	return headers
}

// PublicKeyJWK return public key JWK.
func (s *Signer) PublicKeyJWK() *jws.JWK {
	return s.publicKey
}

// Printf prints to the given writer.
func Printf(out io.Writer, msg string, args ...interface{}) {
	if _, err := fmt.Fprintf(out, msg, args...); err != nil {
		panic(err)
	}
}

// Println prints a line to the given writer.
func Println(out io.Writer, msg string) {
	if _, err := fmt.Fprintln(out, msg); err != nil {
		panic(err)
	}
}
