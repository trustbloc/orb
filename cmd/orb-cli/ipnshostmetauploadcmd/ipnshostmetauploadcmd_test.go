/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipnshostmetauploadcmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag = "--"
)

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing ipfs url arg", func(t *testing.T) {
		startCmd := GetCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither ipfs-url (command line flag) nor ORB_CLI_IPFS_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing arg name arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, ipfsURL("localhost:8080")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither key-name (command line flag) nor ORB_CLI_KEY_NAME (environment variable) have been set.",
			err.Error())
	})
}

func TestUploadHostMetaDoc(t *testing.T) {
	t.Run("test failed to upload host-meta doc", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL("wrongurl")...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "lookup wrongurl")
	})

	t.Run("key not found", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "{}")
			w.WriteHeader(http.StatusOK)
		}))

		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL(serv.URL)...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "key k1 not found in IPFS")
	})

	t.Run("failed to add ipfs dir", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "api/v0/key") {
				fmt.Fprint(w, `{ "Keys": [ { "Id": "aaa", "Name": "k1" } ] }`)
				w.WriteHeader(http.StatusOK)

				return
			}

			w.WriteHeader(http.StatusInternalServerError)
		}))

		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL(serv.URL)...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to add file to IPFS")
	})

	t.Run("failed to publish webfinger", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "api/v0/key") {
				fmt.Fprint(w, `{ "Keys": [ { "Id": "aaa", "Name": "k1" } ] }`)
				w.WriteHeader(http.StatusOK)

				return
			}
			if strings.Contains(r.URL.String(), "api/v0/add") {
				fmt.Fprint(w, `{ "Bytes": "1", "Hash": "a", "Name": "a", "Size": "10" }`)
				w.WriteHeader(http.StatusOK)

				return
			}

			w.WriteHeader(http.StatusInternalServerError)
		}))

		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL(serv.URL)...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to publish meta-host doc")
	})

	t.Run("success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.String(), "api/v0/key") {
				fmt.Fprint(w, `{ "Keys": [ { "Id": "aaa", "Name": "k1" } ] }`)
				w.WriteHeader(http.StatusOK)

				return
			}
			if strings.Contains(r.URL.String(), "api/v0/add") {
				fmt.Fprint(w, `{ "Bytes": "1", "Hash": "a", "Name": "a", "Size": "10" }`)
				w.WriteHeader(http.StatusOK)

				return
			}

			fmt.Fprint(w, `{ "Name": "a", "Value": "a" }`)
			w.WriteHeader(http.StatusOK)
		}))

		cmd := GetCmd()

		var args []string
		args = append(args, ipfsURL(serv.URL)...)
		args = append(args, keyName("k1")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}

func ipfsURL(value string) []string {
	return []string{flag + ipfsURLFlagName, value}
}

func keyName(value string) []string {
	return []string{flag + keyNameFlagName, value}
}
