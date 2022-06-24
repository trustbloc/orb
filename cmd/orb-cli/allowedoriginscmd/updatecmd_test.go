/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginscmd

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
		cmd.SetArgs([]string{"add"})

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor ORB_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid url arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL")
	})

	t.Run("test missing anchororigin arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg("localhost:8080")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither anchororigin (command line flag) nor ORB_CLI_ANCHOR_ORIGINS (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid anchororigin arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg("localhost:8080")...)
		args = append(args, originArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid anchor origin URI")
	})

	t.Run("add -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, originArg("localhost:8080")...)
		args = append(args, authTokenArg("ADMIN_TOKEN")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})

	t.Run("remove -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"remove"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, originArg("localhost:8080")...)
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

func originArg(value string) []string {
	return []string{flag + originFlagName, value}
}

func authTokenArg(value string) []string {
	return []string{flag + common.AuthTokenFlagName, value}
}
