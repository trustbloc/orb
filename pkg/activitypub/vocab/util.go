/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
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

// EncodeDocument encodes the given document using the given media type and returns
// a string with the encoded data.
func EncodeDocument(doc Document, mediaType MediaType) (string, error) {
	docBytes, err := canonicalizer.MarshalCanonical(doc)
	if err != nil {
		return "", fmt.Errorf("marshal canonical: %w", err)
	}

	return Encode(docBytes, mediaType)
}

// DecodeToDocument decodes the given string using the given media type and returns the decoded document.
func DecodeToDocument(content string, mediaType MediaType) (Document, error) {
	docBytes, err := Decode(content, mediaType)
	if err != nil {
		return nil, err
	}

	doc := make(Document)

	err = json.Unmarshal(docBytes, &doc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}

	return doc, nil
}

// Encode encodes the given content using the given media type and returns
// a string with the encoded data.
func Encode(content []byte, mediaType MediaType) (string, error) {
	switch mediaType {
	case GzipMediaType:
		return GzipCompress(content)
	case JSONMediaType:
		return string(content), nil
	case "":
		return "", fmt.Errorf("media type not specified")
	default:
		return "", fmt.Errorf("unsupported media type [%s]", mediaType)
	}
}

// Decode decodes the given string using the given media type and returns the decoded bytes.
func Decode(content string, mediaType MediaType) ([]byte, error) {
	switch mediaType {
	case GzipMediaType:
		return GzipDecompress(content)
	case JSONMediaType:
		return []byte(content), nil
	case "":
		return nil, fmt.Errorf("media type not specified")
	default:
		return nil, fmt.Errorf("unsupported media type [%s]", mediaType)
	}
}

// GzipCompress compresses the given content with gzip and returns a base64-encoded string.
func GzipCompress(docBytes []byte) (string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)

	if _, err := zw.Write(docBytes); err != nil {
		return "", fmt.Errorf("gzip compress: %w", err)
	}

	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("close gzip writer: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// GzipDecompress decompresses the given base64-encoded string with GZIP.
func GzipDecompress(content string) ([]byte, error) {
	compressedBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("base64 decode content: %w", err)
	}

	buf := bytes.NewBuffer(compressedBytes)

	zr, err := gzip.NewReader(buf)
	if err != nil {
		return nil, fmt.Errorf("new gzip reader: %w", err)
	}

	decompressedBytes, err := ioutil.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}

	return decompressedBytes, nil
}
