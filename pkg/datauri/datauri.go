/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package datauri

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
)

// MediaType defines a type of encoding for content embedded within a data URI.
type MediaType = string

const (
	// MediaTypeDataURIJSON indicates that the contents of the data URL is a plain JSON string.
	MediaTypeDataURIJSON MediaType = "application/json"
	// MediaTypeDataURIGzipBase64 indicates that the contents of the data URL is compressed with gzip and base64-encoded.
	MediaTypeDataURIGzipBase64 MediaType = "application/gzip;base64"
)

const numDataURISegments = 2

// New encodes the given content using the given media type and returns
// a data URI with the encoded data. For example: 'data:application/gzip;base64,H4sIAbAAvAAA...'.
func New(content []byte, dataType MediaType) (*url.URL, error) {
	encodedData, err := encode(content, dataType)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(fmt.Sprintf("data:%s,%s", dataType, encodedData))
	if err != nil {
		return nil, fmt.Errorf("parse data URI: %w", err)
	}

	return u, nil
}

// MarshalCanonical marshals and encodes the given object using the given media type and returns
// a data URI with the encoded data. For example: 'data:application/gzip;base64,H4sIAbAAvAAA...'.
func MarshalCanonical(obj interface{}, dataType MediaType) (*url.URL, error) {
	content, err := canonicalizer.MarshalCanonical(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical: %w", err)
	}

	return New(content, dataType)
}

// Decode decodes the given data URI and returns the decoded bytes.
func Decode(u *url.URL) ([]byte, error) {
	if u.Scheme != "data" {
		return nil, errors.New("invalid scheme for data URI")
	}

	segments := strings.Split(u.Opaque, ",")

	if len(segments) < numDataURISegments {
		return nil, fmt.Errorf("no content in data URI: %s", u)
	}

	return decode(segments[1], segments[0])
}

// encode encodes the given content using the given media type and returns
// a string with the encoded data.
func encode(content []byte, mediaType MediaType) (string, error) {
	switch mediaType {
	case MediaTypeDataURIGzipBase64:
		return GzipCompress(content)
	case MediaTypeDataURIJSON:
		return url.QueryEscape(string(content)), nil
	case "":
		return "", fmt.Errorf("media type not specified")
	default:
		return "", fmt.Errorf("unsupported media type [%s]", mediaType)
	}
}

// decode decodes the given string using the given media type and returns the decoded bytes.
func decode(content string, mediaType MediaType) ([]byte, error) {
	switch mediaType {
	case MediaTypeDataURIGzipBase64:
		return GzipDecompress(content)
	case MediaTypeDataURIJSON:
		c, err := url.QueryUnescape(content)
		if err != nil {
			return nil, fmt.Errorf("unescape content: %w", err)
		}

		return []byte(c), nil
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

	zr, err := gzip.NewReader(bytes.NewBuffer(compressedBytes))
	if err != nil {
		return nil, fmt.Errorf("new gzip reader: %w", err)
	}

	decompressedBytes, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}

	return decompressedBytes, nil
}
