/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package hashlink

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
)

const (
	exampleContent = "Hello World!"
	exampleURL     = "https://example.com/hw.txt"

	invalidMultihashCode = 55
)

func TestHashLink_CreateHashLink(t *testing.T) {
	t.Run("success - defaults", func(t *testing.T) {
		hl := New()
		hash, err := hl.CreateHashLink([]byte(exampleContent), nil)
		require.NoError(t, err)
		require.Equal(t, "hl:uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ", hash)
	})

	t.Run("success - activity pub test case values", func(t *testing.T) {
		expectedResourceHash := "uEiB0I06Yr-dJj7Xa8fNqwteKzDOUZPlQcDuMAZiS-YK5Cw"
		expectedMetadata := "uoQ-BeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQjBJMDZZci1kSmo3WGE4Zk5xd3RlS3pET1VaUGxRY0R1TUFaaVMtWUs1Q3c"

		hl := New()
		hash, err := hl.CreateHashLink([]byte("null"), []string{"https://orb.domain1.com/cas/" + expectedResourceHash})
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("hl:%s:%s", expectedResourceHash, expectedMetadata), hash)
	})

	t.Run("success - base58 encoder", func(t *testing.T) {
		hl := New(WithEncoder(base58Encoder))
		hash, err := hl.CreateHashLink([]byte(exampleContent), nil)
		require.NoError(t, err)
		require.Equal(t, "hl:zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e", hash)
	})

	t.Run("success - with link", func(t *testing.T) {
		hl := New(WithEncoder(base58Encoder))
		hash, err := hl.CreateHashLink([]byte(exampleContent), []string{exampleURL})
		require.NoError(t, err)
		require.Equal(t, "hl:zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e:z3TSgXTuaHxY2tsArhUreJ4ixgw9NW7DYuQ9QTPQyLHy", hash)
	})

	t.Run("success - with links", func(t *testing.T) {
		links := []string{
			"https://example.com/cas/uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg",
			"ipfs://QmUB9Nr7RpqNYQpyh4W9r3RQNttiPQ6BQ9iQLkw9LztJFz",
		}

		hl := New()
		hash, err := hl.CreateHashLink([]byte(exampleContent), links)
		require.NoError(t, err)
		require.Equal(t, "hl:uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ:uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3g1aXBmczovL1FtVUI5TnI3UnBxTllRcHloNFc5cjNSUU50dGlQUTZCUTlpUUxrdzlMenRKRno", hash)

		mdLinks, err := hl.GetLinksFromMetadata("uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3g1aXBmczovL1FtVUI5TnI3UnBxTllRcHloNFc5cjNSUU50dGlQUTZCUTlpUUxrdzlMenRKRno")
		require.NoError(t, err)
		require.Equal(t, links, mdLinks)
	})

	t.Run("error - failed to create resource hash", func(t *testing.T) {
		hl := New(WithMultihashCode(invalidMultihashCode))
		hash, err := hl.CreateHashLink([]byte(exampleContent), nil)
		require.Error(t, err)
		require.Empty(t, hash)
		require.Contains(t, err.Error(),
			"failed to compute multihash for code[55]: algorithm not supported, unable to compute hash")
	})
}

func TestHashLink_GetLinksFromMetadata(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		links := []string{
			"https://example.com/cas/uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg",
			"ipfs://QmUB9Nr7RpqNYQpyh4W9r3RQNttiPQ6BQ9iQLkw9LztJFz",
		}

		hl := New()
		md, err := hl.CreateMetadataFromLinks(links)
		require.NoError(t, err)
		require.Equal(t, "uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3g1aXBmczovL1FtVUI5TnI3UnBxTllRcHloNFc5cjNSUU50dGlQUTZCUTlpUUxrdzlMenRKRno", md)

		mdLinks, err := hl.GetLinksFromMetadata(md)
		require.NoError(t, err)
		require.Equal(t, links, mdLinks)
	})

	t.Run("error - failed to decode metadata", func(t *testing.T) {
		hl := New()

		mdLinks, err := hl.GetLinksFromMetadata("xxxabc")
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "failed to decode metadata")
	})

	t.Run("error - failed to unmarshal metadata", func(t *testing.T) {
		hl := New()

		mdLinks, err := hl.GetLinksFromMetadata("invalid")
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "invalid hashlink")
	})

	t.Run("error - links is not array", func(t *testing.T) {
		hl := New()

		metadata := make(map[int]interface{})
		metadata[linksKey] = "just-string"

		bytes, err := cbor.Marshal(metadata)
		require.NoError(t, err)

		mdLinks, err := hl.GetLinksFromMetadata(hl.encoder(bytes))
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "failed to convert links from metadata to string array: expecting an array, got 'string'")
		hl.encoder(bytes)
	})

	t.Run("error - links is not string array", func(t *testing.T) {
		hl := New()

		metadata := make(map[int]interface{})
		metadata[linksKey] = []int{1}

		bytes, err := cbor.Marshal(metadata)
		require.NoError(t, err)

		mdLinks, err := hl.GetLinksFromMetadata(hl.encoder(bytes))
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "failed to convert links from metadata to string array: expecting string, got 'uint64'")
		hl.encoder(bytes)
	})

	t.Run("error - links is nil", func(t *testing.T) {
		hl := New()

		// generate the encoded metadata
		metadata := make(map[int]interface{})
		metadata[linksKey] = nil

		bytes, err := cbor.Marshal(metadata)
		require.NoError(t, err)

		mdLinks, err := hl.GetLinksFromMetadata(hl.encoder(bytes))
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "failed to convert links from metadata to string array: obj is nil")
		hl.encoder(bytes)
	})

	t.Run("error - no links key", func(t *testing.T) {
		hl := New()

		// generate the encoded metadata
		metadata := make(map[int]interface{})

		bytes, err := cbor.Marshal(metadata)
		require.NoError(t, err)

		mdLinks, err := hl.GetLinksFromMetadata(hl.encoder(bytes))
		require.Error(t, err)
		require.Nil(t, mdLinks)
		require.Contains(t, err.Error(), "failed to get links from metadata: missing key")
		hl.encoder(bytes)
	})
}

func TestHashLink_CreateResourceHash(t *testing.T) {
	t.Run("success - defaults", func(t *testing.T) {
		hl := New()

		rh, err := hl.CreateResourceHash([]byte(exampleContent))
		require.NoError(t, err)
		require.Equal(t, "uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ", rh)
	})

	t.Run("error - multihash code not supported", func(t *testing.T) {
		hl := New(WithMultihashCode(invalidMultihashCode))

		rh, err := hl.CreateResourceHash([]byte(exampleContent))
		require.Error(t, err)
		require.Empty(t, rh)
		require.Contains(t, err.Error(),
			"failed to compute multihash for code[55]: algorithm not supported, unable to compute hash")
	})
}

func TestHashLink_CreateMetadataFromLinks(t *testing.T) {
	t.Run("success - with links", func(t *testing.T) {
		links := []string{
			"https://example.com/cas/uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg",
			"ipfs://QmUB9Nr7RpqNYQpyh4W9r3RQNttiPQ6BQ9iQLkw9LztJFz",
		}

		hl := New()

		md, err := hl.CreateMetadataFromLinks(links)
		require.NoError(t, err)
		require.Equal(t, "uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3g1aXBmczovL1FtVUI5TnI3UnBxTllRcHloNFc5cjNSUU50dGlQUTZCUTlpUUxrdzlMenRKRno", md)
	})

	t.Run("error - links not provided", func(t *testing.T) {
		hl := New()

		md, err := hl.CreateMetadataFromLinks(nil)
		require.Error(t, err)
		require.Empty(t, md)
		require.Contains(t, err.Error(), "links not provided")
	})
}

func TestHashLink_ParseHashLink(t *testing.T) {
	t.Run("success - defaults", func(t *testing.T) {
		hl := New()

		hash, err := hl.CreateHashLink([]byte(exampleContent), nil)
		require.NoError(t, err)
		require.Equal(t, "hl:uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ", hash)

		hlInfo, err := hl.ParseHashLink(hash)
		require.NoError(t, err)
		require.Equal(t, "uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ", hlInfo.ResourceHash)
		require.Empty(t, hlInfo.Links)
	})

	t.Run("success - with link", func(t *testing.T) {
		hl := New(WithEncoder(base58Encoder), WithDecoder(base58Decoder))
		hash, err := hl.CreateHashLink([]byte(exampleContent), []string{exampleURL})
		require.NoError(t, err)
		require.Equal(t, "hl:zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e:z3TSgXTuaHxY2tsArhUreJ4ixgw9NW7DYuQ9QTPQyLHy", hash)

		hlInfo, err := hl.ParseHashLink(hash)
		require.NoError(t, err)
		require.Equal(t, "zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e", hlInfo.ResourceHash)
		require.Equal(t, []string{exampleURL}, hlInfo.Links)
	})

	t.Run("success - with links", func(t *testing.T) {
		testRH := "uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ"
		testMD := "uoQ-CeEdodHRwczovL2V4YW1wbGUuY29tL2Nhcy91RWlBc2l3amFYT1lEbU9IeG12RGwzTXgwVGZKMHVDYXI1WVhxdW1qRkpVTklCZ3g1aXBmczovL1FtVUI5TnI3UnBxTllRcHloNFc5cjNSUU50dGlQUTZCUTlpUUxrdzlMenRKRno"
		testHL := GetHashLink(testRH, testMD)

		links := []string{
			"https://example.com/cas/uEiAsiwjaXOYDmOHxmvDl3Mx0TfJ0uCar5YXqumjFJUNIBg",
			"ipfs://QmUB9Nr7RpqNYQpyh4W9r3RQNttiPQ6BQ9iQLkw9LztJFz",
		}

		hl := New()

		hlInfo, err := hl.ParseHashLink(testHL)
		require.NoError(t, err)
		require.Equal(t, testRH, hlInfo.ResourceHash)
		require.Equal(t, links, hlInfo.Links)
	})

	t.Run("error - must start with hl: prefix", func(t *testing.T) {
		hl := New()

		hlInfo, err := hl.ParseHashLink("invalid")
		require.Error(t, err)
		require.Nil(t, hlInfo)
		require.Contains(t, err.Error(), "hashlink 'invalid' must start with 'hl:' prefix")
	})

	t.Run("error - invalid number of parts", func(t *testing.T) {
		hl := New()

		hlInfo, err := hl.ParseHashLink("hl:resource:metadata:invalid")
		require.Error(t, err)
		require.Nil(t, hlInfo)
		require.Contains(t, err.Error(), "hashlink[hl:resource:metadata:invalid] has more than 3 parts")
	})

	t.Run("error - invalid hash", func(t *testing.T) {
		hl := New()

		hlInfo, err := hl.ParseHashLink("hl:abc")
		require.Error(t, err)
		require.Nil(t, hlInfo)
		require.Contains(t, err.Error(),
			"resource hash[abc] for hashlink[hl:abc] is not a valid multihash: failed to decode encoded multihash")
	})

	t.Run("error - multi hash not supported", func(t *testing.T) {
		hl := New(WithMultihashCode(0))

		hlInfo, err := hl.ParseHashLink("hl:uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ")
		require.Error(t, err)
		require.Nil(t, hlInfo)
		require.Contains(t, err.Error(),
			"resource multihash code[18] is not supported code[0]")
	})

	t.Run("error - parse metadata error", func(t *testing.T) {
		hl := New()

		hlInfo, err := hl.ParseHashLink("hl:uEiB_g7Flf_H8U7ktwYFIodZd_C1LH6PWdyhK3dIAEm2QaQ:abc")
		require.Error(t, err)
		require.Nil(t, hlInfo)
		require.Contains(t, err.Error(),
			"failed to get links from metadata: failed to decode metadata: invalid hashlink")
	})
}

func TestGetHashLink(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		hl := GetHashLink("resource", "metadata")
		require.Equal(t, "hl:resource:metadata", hl)
	})
}

func TestGetHashLinkFromResourceHash(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		hl := GetHashLinkFromResourceHash("resource")
		require.Equal(t, "hl:resource", hl)
	})
}

func TestGetResourceHashFromHashLink(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rh, err := GetResourceHashFromHashLink("hl:resource")
		require.NoError(t, err)
		require.Equal(t, "resource", rh)
	})
	t.Run("error", func(t *testing.T) {
		rh, err := GetResourceHashFromHashLink("hl-resource")
		require.Error(t, err)
		require.Contains(t, err.Error(), "hashlink[hl-resource] must start with 'hl:' prefix")
		require.Empty(t, rh)
	})
}

func TestToString(t *testing.T) {
	const (
		hl1 = "hl:uEiC8e7XhtySK1lYVLTIiAi66FAEmmxdiu2_EwVkJYTlsLw:uoQ-CeEtodHRwczovL29yYi5kb21haW4xLmNvbS9jYXMvdUVpQzhlN1hodHlTSzFsWVZMVElpQWk2NkZBRW1teGRpdTJfRXdWa0pZVGxzTHd4QmlwZnM6Ly9iYWZrcmVpZjRwbzI2ZG56ZXJsbGZtZmpuZ2lyYWVsdjJjcWFzbmd5eG1rNXc3cmdibGVld2NvbG1mNA"
		hl2 = "xx:xxx"
	)

	str := ToString(testutil.MustParseURL(hl1), testutil.MustParseURL(hl2))
	require.Equal(t, "{Hash [uEiC8e7XhtySK1lYVLTIiAi66FAEmmxdiu2_EwVkJYTlsLw], Links [https://orb.domain1.com/cas/uEiC8e7XhtySK1lYVLTIiAi66FAEmmxdiu2_EwVkJYTlsLw ipfs://bafkreif4po26dnzerllfmfjngiraelv2cqasngyxmk5w7rgbleewcolmf4]}, {INVALID HASHLINK [xx:xxx]}", str)
}

var base58Encoder = func(data []byte) string {
	return "z" + base58.Encode(data)
}

var base58Decoder = func(enc string) ([]byte, error) {
	return base58.Decode(enc[1:]), nil
}
