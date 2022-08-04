/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package logcmd

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
)

func TestUpdateCmd(t *testing.T) {
	t.Run("test missing url arg", func(t *testing.T) {
		cmd := GetCmd()
		cmd.SetArgs([]string{"update"})

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor ORB_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid url arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"update"}
		args = append(args, urlArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL")
	})

	t.Run("test missing log arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"update"}
		args = append(args, urlArg("localhost:8080")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither log (command line flag) nor ORB_CLI_LOG (environment variable) have been set.",
			err.Error())
	})

	t.Run("update -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "https://vct.com/log")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"update"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, logArg("https://vct.com/log")...)
		args = append(args, authTokenArg("ADMIN_TOKEN")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})

	t.Run("update -> failed", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "https://vct.com/log1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"update"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, logArg("https://vct.com/log")...)
		args = append(args, authTokenArg("ADMIN_TOKEN")...)
		args = append(args, maxRetryArg("2")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"update log failed max retries exhausted check server logs for more info",
			err.Error())
	})
}

func urlArg(value string) []string {
	return []string{flag + urlFlagName, value}
}

func logArg(value string) []string {
	return []string{flag + logFlagName, value}
}

func authTokenArg(value string) []string {
	return []string{flag + common.AuthTokenFlagName, value}
}

func maxRetryArg(value string) []string {
	return []string{flag + maxRetryFlagName, value}
}
