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

func getStaticTime() time.Time {
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		panic(err)
	}

	return time.Date(2021, time.January, 27, 9, 30, 10, 0, loc)
}
