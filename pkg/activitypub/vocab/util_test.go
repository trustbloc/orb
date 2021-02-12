/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshalToDoc(t *testing.T) {
	obj := &mockObject1{
		Field1: "field1",
		Field2: 2,
	}

	doc, err := MarshalToDoc(obj)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, "field1", doc["Field1"])
	require.Equal(t, float64(2), doc["Field2"])

	doc, err = MarshalToDoc(func() {})
	require.Error(t, err)
	require.Nil(t, doc)
}

func TestMustUnmarshalToDoc(t *testing.T) {
	const (
		jsonObj        = `{"Field1":"field1","Field2":2}`
		jsonInvalidObj = `{"Field1":field1","Field2":2}`
	)

	doc := MustUnmarshalToDoc([]byte(jsonObj))
	require.NotNil(t, doc)
	require.Equal(t, "field1", doc["Field1"])
	require.Equal(t, float64(2), doc["Field2"])

	require.Panics(t, func() {
		require.NotNil(t, MustUnmarshalToDoc([]byte(jsonInvalidObj)))
	})
}

func TestMarshalJSON(t *testing.T) {
	const (
		jsonObj = `{"Field1":"field1","Field2":2,"Field3":"field3","Field4":"field4"}`
	)

	obj1 := &mockObject1{
		Field1: "field1",
		Field2: 2,
	}

	obj2 := &mockObject2{
		Field1: "fieldXXX", // Should be ignored
		Field3: "field3",
	}

	obj3 := map[string]interface{}{"Field4": "field4"}

	bytes, err := MarshalJSON(obj1, obj2, obj3)
	require.NoError(t, err)

	require.Equal(t, jsonObj, string(bytes))
}

type mockObject1 struct {
	Field1 string
	Field2 int
}

type mockObject2 struct {
	Field1 string
	Field3 string
}
