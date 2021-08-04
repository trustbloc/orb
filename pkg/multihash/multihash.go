/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package multihash contains functions for converting between multihashes and CIDs.
package multihash

import (
	"fmt"
	"strings"

	gocid "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	mh "github.com/multiformats/go-multihash"
)

// IsValidCID returns true if value passed in is a valid CID.
func IsValidCID(value string) bool {
	if strings.HasPrefix(value, "/ipns/") {
		return true
	}

	cid, err := gocid.Decode(value)
	if err != nil {
		return false
	}

	if cid.String() != value {
		return false
	}

	return true
}

// ToV0CID takes a multibase-encoded multihash and converts it to a V0 CID.
func ToV0CID(multibaseEncodedMultihash string) (string, error) {
	multihash, err := getMultihashFromMultibaseEncodedMultihash(multibaseEncodedMultihash)
	if err != nil {
		return "", err
	}

	return gocid.NewCidV0(multihash).String(), nil
}

// ToV1CID takes a multibase-encoded multihash and converts it to a V1 CID.
func ToV1CID(multibaseEncodedMultihash string) (string, error) {
	multihash, err := getMultihashFromMultibaseEncodedMultihash(multibaseEncodedMultihash)
	if err != nil {
		return "", err
	}

	return gocid.NewCidV1(gocid.Raw, multihash).String(), nil
}

// CIDToMultihash takes a V0 or V1 CID and converts it to a multibase-encoded (with base64url as the base) multihash.
func CIDToMultihash(cid string) (string, error) {
	parsedCID, err := gocid.Decode(cid)
	if err != nil {
		return "", fmt.Errorf("failed to decode CID: %w", err)
	}

	multihashFromCID := parsedCID.Hash()

	multibaseEncodedMultihash, err := multibase.Encode(multibase.Base64url, multihashFromCID)
	if err != nil {
		return "", fmt.Errorf("failed to encoded multihash as a multibase-encoded string: %w", err)
	}

	return multibaseEncodedMultihash, nil
}

func getMultihashFromMultibaseEncodedMultihash(multibaseEncodedMultihash string) (mh.Multihash, error) {
	_, multihashBytes, err := multibase.Decode(multibaseEncodedMultihash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase-encoded multihash: %w", err)
	}

	_, multihash, err := mh.MHFromBytes(multihashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the decoded multibase value as a multihash: %w", err)
	}

	return multihash, nil
}
