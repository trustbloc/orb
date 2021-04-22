/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
)

// MarshalToDoc marshals the given object to a Document.
func MarshalToDoc(obj interface{}) (Document, error) {
	bytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err // nolint: wrapcheck
	}

	return UnmarshalToDoc(bytes)
}

// UnmarshalToDoc unmarshals the given bytes to a Document.
func UnmarshalToDoc(raw []byte) (Document, error) {
	var doc Document

	err := json.Unmarshal(raw, &doc)
	if err != nil {
		return nil, err // nolint: wrapcheck
	}

	return doc, nil
}

// MustUnmarshalToDoc unmarshals the given bytes to a Document.
// If an error occurs then the function panics.
func MustUnmarshalToDoc(raw []byte) Document {
	doc, err := UnmarshalToDoc(raw)
	if err != nil {
		panic(err)
	}

	return doc
}

// MarshalJSON marshals the given objects (merging them into one document) and returns the marshalled JSON result.
func MarshalJSON(o interface{}, others ...interface{}) ([]byte, error) {
	doc, err := MarshalToDoc(o)
	if err != nil {
		return nil, err
	}

	for _, other := range others {
		var otherDoc Document
		if od, ok := other.(Document); !ok {
			otherDoc, err = MarshalToDoc(other)
			if err != nil {
				return nil, err
			}
		} else {
			otherDoc = od
		}

		doc.MergeWith(otherDoc)
	}

	return json.Marshal(doc) // nolint: wrapcheck
}

// UnmarshalJSON unmarshals the given bytes to the set of provided objects.
func UnmarshalJSON(bytes []byte, objects ...interface{}) error {
	for _, obj := range objects {
		err := json.Unmarshal(bytes, obj)
		if err != nil {
			return err // nolint: wrapcheck
		}
	}

	return nil
}
