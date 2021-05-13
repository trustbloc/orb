/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package followcmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag = "--"
)

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))
	defer os.Clearenv()

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing outbox url arg", func(t *testing.T) {
		startCmd := GetCmd()

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither outbox-url (command line flag) nor ORB_CLI_OUTBOX_URL (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing actor arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither actor (command line flag) nor ORB_CLI_ACTOR (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing to arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("actor")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither to (command line flag) nor ORB_CLI_TO (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing action arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither action (command line flag) nor ORB_CLI_ACTION (environment variable) have been set.",
			err.Error())
	})

	t.Run("test missing followID arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		args = append(args, action("Undo")...)

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither follow-id (command line flag) nor ORB_CLI_FOLLOW_ID (environment variable) have been set.",
			err.Error())
	})

	t.Run("test action value not supported", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		args = append(args, action("wrong")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"action wrong not supported",
			err.Error())
	})
}

func TestCreateDID(t *testing.T) {
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := fmt.Fprint(w, "d1")
		require.NoError(t, err)
	}))

	t.Run("test failed to create did", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCmd()

		var args []string
		args = append(args, outboxURL("wrongurl")...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		args = append(args, action("Undo")...)
		args = append(args, followID("followID")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send http request")
	})

	t.Run("success", func(t *testing.T) {
		cmd := GetCmd()

		var args []string
		args = append(args, outboxURL(serv.URL)...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		args = append(args, action("Follow")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})
}

func outboxURL(value string) []string {
	return []string{flag + outboxURLFlagName, value}
}

func actor(value string) []string {
	return []string{flag + actorFlagName, value}
}

func to(value string) []string {
	return []string{flag + toFlagName, value}
}

func action(value string) []string {
	return []string{flag + actionFlagName, value}
}

func followID(value string) []string {
	return []string{flag + followIDFlagName, value}
}
