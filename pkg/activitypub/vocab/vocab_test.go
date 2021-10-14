/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDocument_MergeWith(t *testing.T) {
	const (
		field1 = "Field1"
		field2 = "Field2"
		field3 = "Field3"
		field4 = "Field4"
	)

	doc1 := Document{
		field1: "Value1",
		field3: 3,
	}

	doc2 := Document{
		field2: "Value2",
		field4: 4,
	}

	doc1.MergeWith(doc2)
	require.Equal(t, "Value1", doc1[field1])
	require.Equal(t, "Value2", doc1[field2])
	require.Equal(t, 3, doc1[field3])
	require.Equal(t, 4, doc1[field4])
}

func TestDocument_Unmarshal(t *testing.T) {
	const (
		field1 = "Field1"
		field2 = "Field2"
		value1 = "Value1"
		value2 = 3
	)

	type contentType struct {
		Field1 string
		Field2 int
	}

	doc := Document{
		field1: value1,
		field2: value2,
	}

	contentObj := &contentType{}
	require.NoError(t, doc.Unmarshal(contentObj))
	require.Equal(t, value1, contentObj.Field1)
	require.Equal(t, value2, contentObj.Field2)
}

func TestMustParseURL(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		const iri = "https://example.com"

		require.Equal(t, iri, MustParseURL(iri).String())
	})

	t.Run("Panic", func(t *testing.T) {
		require.Panics(t, func() {
			MustParseURL(string([]byte{0}))
		})
	})
}

func getStaticTime() time.Time {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		panic(err)
	}

	return time.Date(2021, time.January, 27, 9, 30, 10, 0, loc)
}
