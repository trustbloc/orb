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
)

func TestGetCmd(t *testing.T) {
	t.Run("test missing url arg", func(t *testing.T) {
		cmd := GetCmd()
		cmd.SetArgs([]string{"get"})

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither url (command line flag) nor ORB_CLI_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid url arg", func(t *testing.T) {
		cmd := GetCmd()

		args := []string{"get"}
		args = append(args, urlArg(":invalid")...)
		cmd.SetArgs(args)

		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid URL")
	})

	t.Run("success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := fmt.Fprint(w, "d1")
			require.NoError(t, err)
		}))

		cmd := GetCmd()

		args := []string{"get"}
		args = append(args, urlArg(serv.URL)...)
		args = append(args, statusArg("active")...)
		cmd.SetArgs(args)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}
