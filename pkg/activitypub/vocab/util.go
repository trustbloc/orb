/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// MarshalToDoc marshals the given object to a Document.
func MarshalToDoc(obj interface{}) (Document, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	return UnmarshalToDoc(b)
}

// MustMarshalToDoc marshals the given object to a Document.
func MustMarshalToDoc(obj interface{}) Document {
	doc, err := MarshalToDoc(obj)
	if err != nil {
		panic(err)
	}

	return doc
}

// UnmarshalToDoc unmarshals the given bytes to a Document.
func UnmarshalToDoc(raw []byte) (Document, error) {
	var doc Document

	err := json.Unmarshal(raw, &doc)
	if err != nil {
		return nil, err
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

// UnmarshalFromDoc unmarshals the given document to the given object.
func UnmarshalFromDoc(doc Document, obj interface{}) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	err = json.Unmarshal(raw, obj)
	if err != nil {
		return err
	}

	return nil
}

// MustUnmarshalFromDoc unmarshals the given document to the given object.
func MustUnmarshalFromDoc(doc Document, obj interface{}) {
	if err := UnmarshalFromDoc(doc, obj); err != nil {
		panic(err)
	}
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

	return Marshal(doc)
}

// UnmarshalJSON unmarshals the given bytes to the set of provided objects.
func UnmarshalJSON(b []byte, objects ...interface{}) error {
	for _, obj := range objects {
		if err := json.Unmarshal(b, obj); err != nil {
			return err
		}
	}

	return nil
}

// Marshal marshals the given object to a JSON representation without
// escaping characters such as '&', '<' and '>'.
func Marshal(o interface{}) ([]byte, error) {
	b := &bytes.Buffer{}
	encoder := json.NewEncoder(b)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(o); err != nil {
		return nil, err
	}

	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// MustParseURL parses the string and returns the URL.
// This function panics if the string is not a valid URL.
func MustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}

	return u
}
