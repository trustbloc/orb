/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vctcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
)

const (
	flag = "--"
)

func TestVerifyCmd(t *testing.T) {
	t.Run("test missing cas-url arg", func(t *testing.T) {
		cmd := GetCmd()
		cmd.SetArgs([]string{"verify"})

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither cas-url (command line flag) nor ORB_CAS_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid url arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"verify"}
		args = append(args, urlArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "missing protocol scheme")
	})

	t.Run("test missing anchor arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"verify"}
		args = append(args, urlArg("localhost:8080")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchor (command line flag) nor ORB_CLI_ANCHOR (environment variable) have been set.",
			err.Error())
	})

	t.Run("verify -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, anchorLinkset)
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"verify"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, anchorHashArg("uEiDuIicNljP8PoHJk6_aA7w1d4U3FAvDMfF7Dsh7fkw3Wg")...)
		args = append(args, verboseArg(true)...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}

func TestExecuteVerify(t *testing.T) {
	const anchorHash = "uEiDuIicNljP8PoHJk6_aA7w1d4U3FAvDMfF7Dsh7fkw3Wg"

	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, anchorLinkset)
		require.NoError(t, err)
	}))

	t.Run("success", func(t *testing.T) {
		vctClient := &mockVCTClient{
			getSTHResponse: &command.GetSTHResponse{},
			getProofByHashResponse: &command.GetProofByHashResponse{
				LeafIndex: 1000,
				AuditPath: [][]byte{[]byte("fsfsfei34893hwjkh")},
			},
		}

		cmd := newVerifyCmd(&mockVCTClientProvider{client: vctClient})

		out := bytes.NewBuffer(nil)
		cmd.SetOut(out)

		args := []string{}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, anchorHashArg(anchorHash)...)
		args = append(args, verboseArg(true)...)
		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)

		outStr := out.String()

		require.Containsf(t, outStr, "Anchor linkset:", "Output should contain anchor linkset in verbose mode")
		require.Contains(t, outStr, `"found": true`)
		require.Contains(t, outStr, `"leafIndex": 1000`)
	})

	t.Run("no proof -> success", func(t *testing.T) {
		vctClient := &mockVCTClient{
			getSTHResponse:    &command.GetSTHResponse{},
			getProofByHashErr: errors.New("no proof"),
		}

		cmd := newVerifyCmd(&mockVCTClientProvider{client: vctClient})

		out := bytes.NewBuffer(nil)
		cmd.SetOut(out)

		args := []string{}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, anchorHashArg(anchorHash)...)
		args = append(args, verboseArg(true)...)
		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)

		outStr := out.String()

		require.Contains(t, outStr, `"found": false`)
	})

	t.Run("getProofByHash error", func(t *testing.T) {
		vctClient := &mockVCTClient{
			getSTHResponse:    &command.GetSTHResponse{},
			getProofByHashErr: errors.New("injected error"),
		}

		cmd := newVerifyCmd(&mockVCTClientProvider{client: vctClient})

		out := bytes.NewBuffer(nil)
		cmd.SetOut(out)

		args := []string{}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, anchorHashArg(anchorHash)...)
		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)

		outStr := out.String()

		require.NotContainsf(t, outStr, "Anchor linkset:",
			"Output should not contain anchor linkset in non-verbose mode")
		require.Contains(t, outStr, `"error": "injected error"`)
	})

	t.Run("getSTH error", func(t *testing.T) {
		vctClient := &mockVCTClient{
			getSTHErr: errors.New("injected error"),
		}

		cmd := newVerifyCmd(&mockVCTClientProvider{client: vctClient})

		out := bytes.NewBuffer(nil)
		cmd.SetOut(out)

		args := []string{}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, anchorHashArg(anchorHash)...)
		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)

		outStr := out.String()

		require.Contains(t, outStr, `"error": "injected error"`)
	})
}

func urlArg(value string) []string {
	return []string{flag + casURLFlagName, value}
}

func anchorHashArg(value string) []string {
	return []string{flag + anchorHashFlagName, value}
}

func verboseArg(value bool) []string {
	return []string{flag + verboseFlagName, strconv.FormatBool(value)}
}

type mockVCTClient struct {
	getSTHResponse         *command.GetSTHResponse
	getSTHErr              error
	getProofByHashResponse *command.GetProofByHashResponse
	getProofByHashErr      error
}

func (m *mockVCTClient) GetSTH(ctx context.Context) (*command.GetSTHResponse, error) {
	return m.getSTHResponse, m.getSTHErr
}

func (m *mockVCTClient) GetProofByHash(ctx context.Context, hash string,
	treeSize uint64) (*command.GetProofByHashResponse, error) {
	return m.getProofByHashResponse, m.getProofByHashErr
}

type mockVCTClientProvider struct {
	client *mockVCTClient
}

func (m *mockVCTClientProvider) GetVCTClient(domain string, opts ...vct.ClientOpt) vctClient {
	return m.client
}

//nolint:lll
const anchorLinkset = `{
  "linkset": [
    {
      "anchor": "hl:uEiAb66vKOMWatEz861QsrpvTtEFlqftmfw_zGtX7cAlxBQ",
      "author": "https://orb.domain1.com/services/orb",
      "original": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/0zO3U7CMBjG8Xt5PZ2bjMikZ003F6ZmqSjRGEK2frDCtmI/gEh272bGA46fPPn9L9Cqfm+FA/R1gapnjTaAoGmRzxSxZLOZxvXiXNBSuvxhkdA5vpeT9OO9TPAPk0/0tCJvLpltIYDKu/+3cweLokibOuS6q1Q/CZnuIivMUTFhxwECUE50f2xjhAQEXHGkTY08xhhliqxM9jzH3JPvZCf3cRk7tjzn6etuaVNDXx7r27zNi1nhPykM6wAORkvViquA01TxUJvtCN4c72BYD78BAAD//6YQJM3xAAAA",
          "type": "application/linkset+json"
        }
      ],
      "profile": "https://w3id.org/orb#v0",
      "related": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/zzN4XKaMAAA4HfJ/nbTQEXlnxMspYIXpgjZ9TwIUNCEpCEGG893320/9gDffXdAu/4y1Aq4v++g6EnLJXBBS92r361Kx9Fvu+hYKN8sHIgGKfRe+Rv62SjWjCfzorI5WdHbTwSegJC86Wj9lyslBncyGe2u+sHlx4TL8puegiegu+Lf1Mq6+f+sh/XpZFvl6y1Eu0a9LF7naLmaNdDLDrv5ypDmDY3peq/mzod75ej7uvYVr4JkJIbrrbX8yrvZpbRgWxyfb1sW6/LX8pxnka4OqUB27GVwYSIWhrUvkr2Fp4lpwxj6M7RPWXRI8vSwsFEmzviikgpiLw2QHbPqGTE64j5ytl/LLj9iSVgqMIMd8YhNgupKrIoSe8MLL4XlOaGlCS8R86e1hyG2W4mDVuV9ootAfOb9RpIs1pGJYIHA4/3x/vgTAAD//4Gr2I5/AQAA",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/gzip;base64,H4sIAAAAAAAA/6yU22+bSBjF/5fpazAw3Hla7GAcX4OxTXBVWQMMZmxuheHmKv/7ijRJu7uqNpX6zPnOOd/vQ/MN/BXkGcUdBfpnEFNaVDrLtm07aoVRXp5ZyPEqG5Q4xBklKKnYhgd3P4QCCV9kFQ7qktCerWpCccVe2oqBHOQ+KMchlCReex/5cgd+ZDq1f8EBBTqIE702ieHLcrPYrFxEzZsq83ZVFs2OmtPka0TTqD3dLPqkBEbSjW1wB0g4TL42yEt/FOYpIhk/CvKUbQJWwRgLCsaMAFWVESXoMwhqmFGRKqlIQYEYqYNNVdUoC/A9ohjoAHIQMpzE8NqOV3We1zltBGVZ5AT5+KrG5a+DwR0oyjyPgP7527Aqojj8lavKD47fh18dXw2bgOoqpyhsiooED/DefB/rssiroSiqKlxSkmcrTOM8fBMcUFIPn1e7eFWYXTZ1SYb9aTaPZ6RXxvOnx7hO50mbPyy3h9VX5j7xTqLtLq7ljPOZda8dO89Exbm9CLI8babGRtr7on895w+iMWCnfTH4m98v65BzhmhdvpVscEkiEqCfiukgJKHeYl//F6tP+whtHp37U+EYe9WHJ+vmpMcj7zV7pHbrpbPSpHF0m0nuxQbPd//HUxShIsnCf5j+80rw5yt9mOaGzDUva6RyW8b9AUn+ob2azd7wBM8O80WUW1qsZZZlnTZbaTc1JpvI7mzfFwmMRcPYZAi35/nYa+2d2Xc4dfmwv/9jNF92+sRf07U1m6eTRTdZzjw6ThbqgV7N/TFGxuSSGUrb9z3yzw/ch2hqH/474W/z1FLxYiU7U84bYw7PbrpPjorLOF7bSJYWKYL4RMO1HQV2GXS0uZ7NY6SETrSRGkecFofGu0DOu8Xazbwte5MIydWdGH+Kp/DCc+emC1VkynFSCY/uFLq16GacOV/bg8aVlh7nHrdbczVuwfOX9+jDSwbyEzx5f+nA898BAAD//4dCKH2QBQAA",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
