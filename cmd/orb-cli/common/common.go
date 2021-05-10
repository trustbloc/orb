/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/doc"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
)

// PublicKey struct.
type PublicKey struct {
	ID       string   `json:"id,omitempty"`
	Type     string   `json:"type,omitempty"`
	Purposes []string `json:"purposes,omitempty"`
	JWKPath  string   `json:"jwkPath,omitempty"`
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

	bytes := privBlock.Bytes

	if len(password) != 0 {
		var err error
		// FIXME: x509.DecryptPEMBlock deprecated in go1.16 due to security flaws.
		//   this should be replaced by a different infrastructure for configuring keys before this goes into prod.
		bytes, err = x509.DecryptPEMBlock(privBlock, password) //nolint:staticcheck

		if err != nil {
			return nil, err
		}
	}

	privKey, err := ParsePrivateKey(bytes)
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
func GetVDRPublicKeysFromFile(publicKeyFilePath string) (*docdid.Doc, error) { //nolint:gocyclo,cyclop
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
		jwkData, err := ioutil.ReadFile(filepath.Clean(v.JWKPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read jwk file '%s' : %w", v.JWKPath, err)
		}

		var jsonWebKey gojose.JSONWebKey
		if errUnmarshal := jsonWebKey.UnmarshalJSON(jwkData); errUnmarshal != nil {
			return nil, fmt.Errorf("failed to unmarshal to jwk: %w", errUnmarshal)
		}

		jwk, err := jose.JWKFromKey(jsonWebKey.Key)
		if err != nil {
			return nil, err
		}

		vm, err := docdid.NewVerificationMethodFromJWK(v.ID, v.Type, "", jwk)
		if err != nil {
			return nil, err
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
