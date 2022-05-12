/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package logmonitorcmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

const (
	flag = "--"

	activate   = "activate"
	deactivate = "deactivate"

	testLog = "https://vct.com/log"
)

func TestUpdateCmd(t *testing.T) {
	t.Run("test missing url arg", func(t *testing.T) {
		cmd := GetCmd()
		cmd.SetArgs([]string{"activate"})

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor ORB_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid url arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{activate}
		args = append(args, urlArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL")
	})

	t.Run("test missing logArg arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{activate}
		args = append(args, urlArg("localhost:8080")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither log (command line flag) nor ORB_CLI_LOG (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid logArg arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{activate}
		args = append(args, urlArg(testLog)...)
		args = append(args, logArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid log URL")
	})

	t.Run("activate -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{activate}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, logArg(testLog)...)
		args = append(args, authTokenArg("ADMIN_TOKEN")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})

	t.Run("deactivate -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{deactivate}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, logArg(testLog)...)
		args = append(args, authTokenArg("ADMIN_TOKEN")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}

func urlArg(value string) []string {
	return []string{flag + urlFlagName, value}
}

func logArg(value string) []string {
	return []string{flag + logFlagName, value}
}

func statusArg(value string) []string {
	return []string{flag + statusFlagName, value}
}

func authTokenArg(value string) []string {
	return []string{flag + common.AuthTokenFlagName, value}
}
