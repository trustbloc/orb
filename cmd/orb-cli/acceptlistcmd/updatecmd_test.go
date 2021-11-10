/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package acceptlistcmd

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

	t.Run("test missing type arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg("localhost:8080")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither type (command line flag) nor ORB_CLI_ACCEPT_TYPE (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing actorArg arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg("localhost:8080")...)
		args = append(args, typeArg("follow")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither actor (command line flag) nor ORB_CLI_ACTOR (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid actorArg arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg("localhost:8080")...)
		args = append(args, typeArg("follow")...)
		args = append(args, actorArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid actor URL")
	})

	t.Run("add -> success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"add"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, typeArg("follow")...)
		args = append(args, actorArg("localhost:8080")...)
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
		args = append(args, typeArg("follow")...)
		args = append(args, actorArg("localhost:8080")...)
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

func actorArg(value string) []string {
	return []string{flag + actorFlagName, value}
}

func typeArg(value string) []string {
	return []string{flag + typeFlagName, value}
}

func authTokenArg(value string) []string {
	return []string{flag + common.AuthTokenFlagName, value}
}
