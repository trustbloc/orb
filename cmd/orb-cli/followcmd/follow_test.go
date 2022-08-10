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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

const (
	flag = "--"
)

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetCmd()

	require.NoError(t, os.Setenv(common.TLSSystemCertPoolEnvKey, "wrongvalue"))
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

	t.Run("test invalid 'actor' arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, to("to")...)
		args = append(args, action("Follow")...)
		args = append(args, actor(string([]byte{0x0}))...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid control character in URL")
	})

	t.Run("test missing to arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("http://orb.domain1.com/services/orb")...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither to (command line flag) nor ORB_CLI_TO (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid 'to' arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("localhost:8080")...)
		args = append(args, actor("actor")...)
		args = append(args, to(string([]byte{0x0}))...)
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"parse 'to' URL \u0000: parse \"\\x00\": net/url: invalid control character in URL",
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
		args = append(args, actor("http://orb.domain1.com/services/anchor")...)
		args = append(args, to("to")...)
		args = append(args, action("Undo")...)

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither follow-id (command line flag) nor ORB_CLI_FOLLOW_ID (environment variable) have been set.",
			err.Error())
	})

	t.Run("test invalid 'followID' arg", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL("http://localhost:8080")...)
		args = append(args, actor("actor")...)
		args = append(args, to("to")...)
		args = append(args, action("Undo")...)
		args = append(args, followID(string([]byte{0x0}))...)

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"parse 'followID' URL \u0000: parse \"\\x00\": net/url: invalid control character in URL",
			err.Error())
	})
}

func TestFollow(t *testing.T) {
	const servicePath = "/services/anchor"

	orb1 := httptest.NewServer(getOrb1Handler(t, servicePath))
	orb2 := httptest.NewServer(getOrb2Handler(t, servicePath))
	orb1A := httptest.NewServer(getOrb1AHandler(t, servicePath))

	orb1Domain := strings.Split(orb1.URL, "//")[1]
	orb1ADomain := strings.Split(orb1A.URL, "//")[1]
	orb2Domain := strings.Split(orb1.URL, "//")[1]

	t.Run("test failed to follow", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCmd()

		var args []string
		args = append(args, outboxURL("wrongurl")...)
		args = append(args, actor("http://orb.domain1.com/services/anchor")...)
		args = append(args, to("to")...)
		args = append(args, action("Undo")...)
		args = append(args, followID("followID")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
	})

	t.Run("test action value not supported", func(t *testing.T) {
		startCmd := GetCmd()

		var args []string
		args = append(args, outboxURL(orb1.URL+"/services/anchor/outbox")...)
		args = append(args, actor(orb1.URL+"/services/anchor")...)
		args = append(args, to(orb2.URL+"/services/anchor")...)
		args = append(args, action("wrong")...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain1.com->%s", orb1Domain))...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain2.com->%s", orb2Domain))...)

		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"action wrong not supported",
			err.Error())
	})

	t.Run("Follow -> success", func(t *testing.T) {
		cmd := GetCmd()

		var args []string
		args = append(args, outboxURL(orb1.URL+"/services/anchor/outbox")...)
		args = append(args, actor(orb1.URL+"/services/anchor")...)
		args = append(args, to(orb2.URL+"/services/anchor")...)
		args = append(args, action("Follow")...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain1.com->%s", orb1Domain))...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain2.com->%s", orb2Domain))...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.NoError(t, err)
	})

	t.Run("Undo Follow -> success", func(t *testing.T) {
		t.Logf("Orb1 URL: %s", orb1.URL)
		cmd := GetCmd()

		var args []string
		args = append(args, outboxURL(orb1A.URL+"/services/anchor/outbox")...)
		args = append(args, actor(orb1A.URL+"/services/anchor")...)
		args = append(args, to(orb2.URL+"/services/anchor")...)
		args = append(args, action("Undo")...)
		args = append(args, followID("http://orb.domain1.com/services/orb/activities/123456")...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain1.com->%s", orb1ADomain))...)
		args = append(args, targetOverride(fmt.Sprintf("orb.domain2.com->%s", orb2Domain))...)

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

func targetOverride(value string) []string {
	return []string{flag + common.TargetOverrideFlagName, value}
}

func getOrb1Handler(t *testing.T, servicePath string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.String() == servicePath:
			_, err := fmt.Fprint(w, jsonActor1)
			require.NoError(t, err)
		case r.Method == http.MethodPost && r.URL.String() == fmt.Sprintf("%s/outbox", servicePath):
			w.WriteHeader(http.StatusOK)
		case r.URL.String() == fmt.Sprintf("%s/following", servicePath):
			_, err := fmt.Fprint(w, jsonCollection)
			require.NoError(t, err)
		case r.URL.String() == fmt.Sprintf("%s/following?page=true", servicePath):
			_, err := fmt.Fprint(w, jsonCollectionFirstPage)
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, err := fmt.Fprint(w, "Bad request")
			require.NoError(t, err)
		}
	}
}

func getOrb2Handler(t *testing.T, servicePath string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.String() == servicePath:
			_, err := fmt.Fprint(w, jsonActor2)
			require.NoError(t, err)
		case r.URL.String() == fmt.Sprintf("%s/inbox", servicePath):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, err := fmt.Fprint(w, "Bad request")
			require.NoError(t, err)
		}
	}
}

func getOrb1AHandler(t *testing.T, servicePath string) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.String() == servicePath:
			_, err := fmt.Fprint(w, jsonActor1)
			require.NoError(t, err)
		case r.Method == http.MethodPost && r.URL.String() == fmt.Sprintf("%s/outbox", servicePath):
			w.WriteHeader(http.StatusOK)
		case r.URL.String() == fmt.Sprintf("%s/following", servicePath):
			_, err := fmt.Fprint(w, jsonEmptyCollection)
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, err := fmt.Fprint(w, "Bad request")
			require.NoError(t, err)
		}
	}
}

const (
	jsonActor1 = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "http://orb.domain1.com/services/anchor",
  "publicKey": {
    "id": "http://orb.domain1.com/services/anchor/keys/main-key",
    "owner": "http://orb.domain1.com/services/anchor",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "followers": "http://orb.domain1.com/services/anchor/followers",
  "following": "http://orb.domain1.com/services/anchor/following",
  "inbox": "http://orb.domain1.com/services/anchor/inbox",
  "liked": "http://orb.domain1.com/services/anchor/liked",
  "likes": "http://orb.domain1.com/services/anchor/likes",
  "outbox": "http://orb.domain1.com/services/anchor/outbox",
  "shares": "http://orb.domain1.com/services/anchor/shares",
  "type": "Service",
  "witnesses": "http://orb.domain1.com/services/anchor/witnesses",
  "witnessing": "http://orb.domain1.com/services/anchor/witnessing"
}`

	jsonActor2 = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    "https://w3id.org/activityanchors/v1"
  ],
  "id": "http://orb.domain2.com/services/anchor",
  "publicKey": {
    "id": "http://orb.domain2.com/services/anchor/keys/main-key",
    "owner": "http://orb.domain2.com/services/anchor",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhki....."
  },
  "followers": "http://orb.domain2.com/services/anchor/followers",
  "following": "http://orb.domain2.com/services/anchor/following",
  "inbox": "http://orb.domain2.com/services/anchor/inbox",
  "liked": "http://orb.domain2.com/services/anchor/liked",
  "likes": "http://orb.domain2.com/services/anchor/likes",
  "outbox": "http://orb.domain2.com/services/anchor/outbox",
  "shares": "http://orb.domain2.com/services/anchor/shares",
  "type": "Service",
  "witnesses": "http://orb.domain2.com/services/anchor/witnesses",
  "witnessing": "http://orb.domain2.com/services/anchor/witnessing"
}`

	jsonCollection = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "first": "http://orb.domain1.com/services/anchor/following?page=true",
  "id": "http://orb.domain1.com/services/anchor/following",
  "last": "http://orb.domain1.com/services/anchor/following?page=true&page-num=1",
  "totalItems": 1,
  "type": "Collection"
 }`

	jsonEmptyCollection = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "http://orb.domain1.com/services/anchor/following",
  "totalItems": 0,
  "type": "Collection"
 }`

	jsonCollectionFirstPage = `{
  "@context": "https://www.w3.org/ns/activitystreams",
  "id": "http://orb.domain1.com/services/anchor/following?page=true&page-num=0",
  "next": "http://orb.domain1.com/services/anchor/following?page=true&page-num=1",
  "items": [
    "http://orb.domain2.com/services/anchor"
  ],
  "totalItems": 1,
  "type": "CollectionPage"
 }`
)
