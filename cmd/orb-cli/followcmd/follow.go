/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package followcmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

const (
	outboxURLFlagName  = "outbox-url"
	outboxURLFlagUsage = "Outbox url." +
		" Alternatively, this can be set with the following environment variable: " + outboxURLEnvKey
	outboxURLEnvKey = "ORB_CLI_OUTBOX_URL"

	actorFlagName  = "actor"
	actorFlagUsage = "Actor IRI." +
		" Alternatively, this can be set with the following environment variable: " + actorEnvKey
	actorEnvKey = "ORB_CLI_ACTOR"

	toFlagName  = "to"
	toFlagUsage = "To IRI." +
		" Alternatively, this can be set with the following environment variable: " + toEnvKey
	toEnvKey = "ORB_CLI_TO"

	actionFlagName  = "action"
	actionFlagUsage = "Follower action (Follow, Undo)." +
		" Alternatively, this can be set with the following environment variable: " + actionEnvKey
	actionEnvKey = "ORB_CLI_ACTION"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ORB_CLI_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ORB_CLI_TLS_CACERTS"

	authTokenFlagName  = "auth-token"
	authTokenFlagUsage = "Auth token." +
		" Alternatively, this can be set with the following environment variable: " + authTokenEnvKey
	authTokenEnvKey = "ORB_CLI_AUTH_TOKEN" //nolint:gosec

	followIDFlagName  = "follow-id"
	followIDFlagUsage = "follow id required for undo action." +
		" Alternatively, this can be set with the following environment variable: " + followIDEnvKey
	followIDEnvKey = "ORB_CLI_FOLLOW_ID"
)

const (
	followAction = "Follow"
	undoAction   = "Undo"
	followCtx    = "https://www.w3.org/ns/activitystreams"
)

type follow struct {
	Context []string `json:"@context,omitempty"`
	Type    string   `json:"type,omitempty"`
	Actor   string   `json:"actor,omitempty"`
	To      string   `json:"to,omitempty"`
	Object  string   `json:"object,omitempty"`
}

// GetCmd returns the Cobra follow command.
func GetCmd() *cobra.Command {
	createCmd := createCmd()

	createFlags(createCmd)

	return createCmd
}

func createCmd() *cobra.Command { //nolint:funlen,gocyclo,cyclop
	return &cobra.Command{
		Use:   "follower",
		Short: "manage followers",
		Long:  "manage followers ",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:    rootCAs,
						MinVersion: tls.VersionTLS12,
					},
				},
			}

			outboxURL, err := cmdutils.GetUserSetVarFromString(cmd, outboxURLFlagName,
				outboxURLEnvKey, false)
			if err != nil {
				return err
			}

			actor, err := cmdutils.GetUserSetVarFromString(cmd, actorFlagName,
				actorEnvKey, false)
			if err != nil {
				return err
			}

			to, err := cmdutils.GetUserSetVarFromString(cmd, toFlagName,
				toEnvKey, false)
			if err != nil {
				return err
			}

			action, err := cmdutils.GetUserSetVarFromString(cmd, actionFlagName,
				actionEnvKey, false)
			if err != nil {
				return err
			}

			authToken := cmdutils.GetUserSetOptionalVarFromString(cmd, authTokenFlagName,
				authTokenEnvKey)

			req := follow{Context: []string{followCtx}, Actor: actor, To: to}

			switch action {
			case followAction:
				req.Type = action
				req.Object = to
			case undoAction:
				followID, errGet := cmdutils.GetUserSetVarFromString(cmd, followIDFlagName,
					followIDEnvKey, false)
				if errGet != nil {
					return errGet
				}

				req.Type = action
				req.Object = followID
			default:
				return fmt.Errorf("action %s not supported", action)
			}

			reqBytes, err := json.Marshal(req)
			if err != nil {
				return err
			}

			resp, err := common.SendRequest(httpClient, reqBytes, authToken, http.MethodPost,
				outboxURL)
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			fmt.Printf("success %s id: %s\n", action, resp)

			return nil
		},
	}
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(outboxURLFlagName, "", "", outboxURLFlagUsage)
	startCmd.Flags().StringP(actorFlagName, "", "", actorFlagUsage)
	startCmd.Flags().StringP(toFlagName, "", "", toFlagUsage)
	startCmd.Flags().StringP(actionFlagName, "", "", actionFlagUsage)
	startCmd.Flags().StringP(authTokenFlagName, "", "", authTokenFlagUsage)
	startCmd.Flags().StringP(followIDFlagName, "", "", followIDFlagUsage)
}
