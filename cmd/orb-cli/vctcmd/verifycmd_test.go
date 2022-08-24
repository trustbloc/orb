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
      "anchor": "hl:uEiBcKyZmxMkniU9PHHb932B3Xeqjhg9t2BAtPIwRmhMDeA",
      "author": [
        {
          "href": "did:web:orb.domain2.com:services:orb"
        }
      ],
      "original": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiAP-3ycWtqewqjOA8pUqhUzsLst6NpYeJBWeUn764gD5w%22%2C%22author%22%3A%5B%7B%22href%22%3A%22did%3Aweb%3Aorb.domain2.com%3Aservices%3Aorb%22%7D%5D%2C%22item%22%3A%5B%7B%22href%22%3A%22did%3Aorb%3AuAAA%3AEiC9X_-74fc1I_VrT_hjJVNuU30s2Vk33HqD1pE59jaePQ%22%7D%5D%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "profile": [
        {
          "href": "https://w3id.org/orb#v0"
        }
      ],
      "related": [
        {
          "href": "data:application/json,%7B%22linkset%22%3A%5B%7B%22anchor%22%3A%22hl%3AuEiBcKyZmxMkniU9PHHb932B3Xeqjhg9t2BAtPIwRmhMDeA%22%2C%22profile%22%3A%5B%7B%22href%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%5D%2C%22via%22%3A%5B%7B%22href%22%3A%22hl%3AuEiAP-3ycWtqewqjOA8pUqhUzsLst6NpYeJBWeUn764gD5w%3AuoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQVAtM3ljV3RxZXdxak9BOHBVcWhVenNMc3Q2TnBZZUpCV2VVbjc2NGdENXc%22%7D%5D%7D%5D%7D",
          "type": "application/linkset+json"
        }
      ],
      "replies": [
        {
          "href": "data:application/json,%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww.w3.org%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Factivityanchors%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fjws-2020%2Fv1%22%2C%22https%3A%2F%2Fw3id.org%2Fsecurity%2Fsuites%2Fed25519-2020%2Fv1%22%5D%2C%22credentialSubject%22%3A%7B%22anchor%22%3A%22hl%3AuEiAP-3ycWtqewqjOA8pUqhUzsLst6NpYeJBWeUn764gD5w%22%2C%22id%22%3A%22hl%3AuEiBcKyZmxMkniU9PHHb932B3Xeqjhg9t2BAtPIwRmhMDeA%22%2C%22profile%22%3A%22https%3A%2F%2Fw3id.org%2Forb%23v0%22%7D%2C%22id%22%3A%22https%3A%2F%2Forb.domain2.com%2Fvc%2F12f28162-e842-4731-a604-e6b498c54180%22%2C%22issuanceDate%22%3A%222022-08-24T16%3A09%3A16.258895038Z%22%2C%22issuer%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proof%22%3A%5B%7B%22created%22%3A%222022-08-24T16%3A09%3A16.261047189Z%22%2C%22domain%22%3A%22https%3A%2F%2Forb.domain2.com%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z4EgDBVvFFDLRZLVptnWr5MKjpXCmdzupjgbFvQV64HepY7rx9MzzRU2BFugBqz8qcorLuQpRWH9komMZANfFHyrs%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain2.com%23po7hg_7dAhzXvWGZjb5bpi2cHAMKjwnYtuysmq_yoc4%22%7D%2C%7B%22created%22%3A%222022-08-24T16%3A09%3A16.508Z%22%2C%22domain%22%3A%22http%3A%2F%2Forb.vct%3A8077%2Fmaple2020%22%2C%22proofPurpose%22%3A%22assertionMethod%22%2C%22proofValue%22%3A%22z3TX7xt3dud6akt4BhckANJHEmkkYByjCNCYdLbwWDrF9rkTL3Ft3YdXCCQdefKgpC48dG5yYTzLF4Xv8aM6TSJoM%22%2C%22type%22%3A%22Ed25519Signature2020%22%2C%22verificationMethod%22%3A%22did%3Aweb%3Aorb.domain1.com%23b4RW-vSGuc0bahOVjdcF6pB36k5wRAjvDP71bp7k4uE%22%7D%5D%2C%22type%22%3A%5B%22VerifiableCredential%22%2C%22AnchorCredential%22%5D%7D",
          "type": "application/ld+json"
        }
      ]
    }
  ]
}`
