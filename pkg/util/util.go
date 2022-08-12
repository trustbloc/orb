/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// EncodePublicKeyToPEM returns the PEM-encoding of the given public key.
func EncodePublicKeyToPEM(pubKeyBytes []byte, keyType kms.KeyType) ([]byte, error) {
	keyBytes := pubKeyBytes

	pemKeyType := getPEMKeyType(keyType)

	if keyType == kms.ECDSAP256DER || keyType == kms.ECDSAP384DER || keyType == kms.ECDSAP521DER {
		curveMap := map[string]elliptic.Curve{
			"P-256": elliptic.P256(),
			"P-384": elliptic.P384(),
			"P-521": elliptic.P521(),
		}

		key, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}

		keyBytes = elliptic.Marshal(curveMap[pemKeyType], key.(*ecdsa.PublicKey).X, key.(*ecdsa.PublicKey).Y)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemKeyType,
		Bytes: keyBytes,
	}), nil
}

func getPEMKeyType(keyType kms.KeyType) string {
	switch {
	case strings.HasPrefix(strings.ToUpper(string(keyType)), kms.ED25519):
		return "Ed25519"
	case keyType == kms.ECDSAP256IEEEP1363 || keyType == kms.ECDSAP256DER:
		return "P-256"
	case keyType == kms.ECDSAP384IEEEP1363 || keyType == kms.ECDSAP384DER:
		return "P-384"
	case keyType == kms.ECDSAP521IEEEP1363 || keyType == kms.ECDSAP521DER:
		return "P-521"
	default:
		return ""
	}
}
