/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package diddoctransformer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trustbloc/sidetree-go/pkg/canonicalizer"
	"github.com/trustbloc/sidetree-go/pkg/document"
)

// WebDocumentFromOrbDocument creates did:web document from did:orb resolution result.
// Rules:
// 1. Replace did:orb ID with did:web ID in Orb did document
// 2. add up to two Orb equivalent IDs to also known as
// (equivalentID with discovery domain for unpublished or canonical ID and HL ID for published).
func WebDocumentFromOrbDocument(webDID string, orbResolutionResult *document.ResolutionResult) (document.Document, error) {
	orbDID := getOrbDID(orbResolutionResult)

	didWebDoc, err := transformToDIDWeb(webDID, orbResolutionResult.Document)
	if err != nil {
		return nil, err
	}

	equivalentID, err := getEquivalentID(orbResolutionResult)
	if err != nil {
		return nil, err
	}

	// replace did:web ID with did:orb ID in also known as; if did:web ID is not found then add did:orb ID anyway
	didWebDoc, err = updateAlsoKnownAs(didWebDoc, webDID, orbDID, equivalentID)
	if err != nil {
		return nil, err
	}

	return didWebDoc, nil
}

func updateAlsoKnownAs(didWebDoc document.Document, webDID, orbDID string, equivalentID []string) (document.Document, error) {
	alsoKnownAs, err := getAlsoKnownAs(didWebDoc)
	if err != nil {
		return nil, err
	}

	// replace did:orb value with did:web values
	updatedAlsoKnownAs := updateValues(alsoKnownAs, webDID, orbDID)

	if !contains(updatedAlsoKnownAs, orbDID) {
		updatedAlsoKnownAs = append(updatedAlsoKnownAs, orbDID)
	}

	// unpublished doc has 1 equivalent ID, and published has 2+ (first one is canonical)
	const maxEquivalentIDLength = 2
	count := minimum(maxEquivalentIDLength, len(equivalentID))

	for i := 0; i < count; i++ {
		if !contains(updatedAlsoKnownAs, equivalentID[i]) {
			updatedAlsoKnownAs = append(updatedAlsoKnownAs, equivalentID[i])
		}
	}

	didWebDoc[document.AlsoKnownAs] = updatedAlsoKnownAs

	return didWebDoc, nil
}

func getOrbDID(result *document.ResolutionResult) string {
	canonicalIDObj, ok := result.DocumentMetadata[document.CanonicalIDProperty]
	if ok {
		canonicalID, ok := canonicalIDObj.(string)
		if ok {
			return canonicalID
		}
	}

	return result.Document.ID()
}

func transformToDIDWeb(id string, doc document.Document) (document.Document, error) {
	docBytes, err := doc.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal document for id[%s]: %w", id, err)
	}

	// replace all occurrences of did:orb ID with did:web ID
	didWebDocStr := strings.ReplaceAll(string(docBytes), doc.ID(), id)

	var didWebDoc document.Document

	err = json.Unmarshal([]byte(didWebDocStr), &didWebDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal document for id[%s]: %w", id, err)
	}

	return didWebDoc, nil
}

// updateValues will replace old value with new value in an array of strings.
func updateValues(values []string, oldValue, newValue string) []string {
	for i, v := range values {
		if v == oldValue {
			values[i] = newValue
		}
	}

	return values
}

func getAlsoKnownAs(doc document.Document) ([]string, error) {
	alsoKnownAsObj, ok := doc[document.AlsoKnownAs]
	if !ok || alsoKnownAsObj == nil {
		return nil, nil
	}

	alsoKnownAsObjArr, ok := alsoKnownAsObj.([]interface{})
	if ok {
		return document.StringArray(alsoKnownAsObjArr), nil
	}

	alsoKnownAsStrArr, ok := alsoKnownAsObj.([]string)
	if ok {
		return alsoKnownAsStrArr, nil
	}

	return nil, fmt.Errorf("unexpected interface '%T' for also known as", alsoKnownAsObj)
}

func getEquivalentID(result *document.ResolutionResult) ([]string, error) {
	equivalentIDObj, ok := result.DocumentMetadata[document.EquivalentIDProperty]
	if !ok {
		return nil, nil
	}

	equivalentIDArr, ok := equivalentIDObj.([]interface{})
	if ok {
		return document.StringArray(equivalentIDArr), nil
	}

	equivalentIDStrArr, ok := equivalentIDObj.([]string)
	if ok {
		return equivalentIDStrArr, nil
	}

	return nil, fmt.Errorf("unexpected interface '%T' for equivalentId", equivalentIDObj)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}

	return false
}

func minimum(a, b int) int {
	if a < b {
		return a
	}

	return b
}

// Equal transforms documents into canonical form and compares them.
// Exclude tags (optional) will be removed from document before comparison.
func Equal(doc1, doc2 document.Document, excludeTags ...string) error {
	for _, tag := range excludeTags {
		delete(doc1, tag)
		delete(doc2, tag)
	}

	doc1Bytes, err := canonicalizer.MarshalCanonical(doc1)
	if err != nil {
		return err
	}

	doc2Bytes, err := canonicalizer.MarshalCanonical(doc2)
	if err != nil {
		return err
	}

	if !bytes.Equal(doc1Bytes, doc2Bytes) {
		return fmt.Errorf("documents [%s] and [%s] do not match", string(doc1Bytes), string(doc2Bytes))
	}

	return nil
}

// VerifyWebDocumentFromOrbDocument will create web document from orb resolution result and compare that web document
// with provided web document for equality.
func VerifyWebDocumentFromOrbDocument(webRR, orbRR *document.ResolutionResult, excludeTags ...string) error {
	webDID := webRR.Document.ID()

	webDocFromOrbDoc, err := WebDocumentFromOrbDocument(webDID, orbRR)
	if err != nil {
		return err
	}

	return Equal(webRR.Document, webDocFromOrbDoc, excludeTags...)
}
