/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package followcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
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

	followIDFlagName  = "follow-id"
	followIDFlagUsage = "follow id required for undo action." +
		" Alternatively, this can be set with the following environment variable: " + followIDEnvKey
	followIDEnvKey = "ORB_CLI_FOLLOW_ID"

	maxRetryFlagName  = "max-retry"
	maxRetryFlagUsage = "max retry to check if follow cmd is succeed default value is 10" +
		" Alternatively, this can be set with the following environment variable: " + maxRetryEnvKey
	maxRetryEnvKey = "ORB_CLI_MAX_RETRY"

	waitTimeFlagName  = "wait-time"
	waitTimeFlagUsage = "wait time between retries default value is 1s" +
		" Alternatively, this can be set with the following environment variable: " + waitTimeEnvKey
	waitTimeEnvKey = "ORB_CLI_WAIT_TIME"
)

const (
	followAction    = "Follow"
	undoAction      = "Undo"
	defaultMaxRetry = 10
	defaultWaitTime = 1 * time.Second
)

// GetCmd returns the Cobra follow command.
func GetCmd() *cobra.Command {
	createCmd := createCmd()

	createFlags(createCmd)

	return createCmd
}

func createCmd() *cobra.Command { //nolint:funlen,gocyclo,cyclop,gocognit
	return &cobra.Command{
		Use:          "follower",
		Short:        "manage followers",
		Long:         "manage followers ",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			httpClient, err := common.NewHTTPClient(cmd)
			if err != nil {
				return err
			}

			authToken := cmdutil.GetUserSetOptionalVarFromString(cmd, common.AuthTokenFlagName,
				common.AuthTokenEnvKey)

			headers := make(map[string]string)
			if authToken != "" {
				headers["Authorization"] = "Bearer " + authToken
			}

			outboxURL, err := cmdutil.GetUserSetVarFromString(cmd, outboxURLFlagName,
				outboxURLEnvKey, false)
			if err != nil {
				return err
			}

			actorIRI, err := cmdutil.GetUserSetVarFromString(cmd, actorFlagName,
				actorEnvKey, false)
			if err != nil {
				return err
			}

			to, err := cmdutil.GetUserSetVarFromString(cmd, toFlagName,
				toEnvKey, false)
			if err != nil {
				return err
			}

			toIRI, err := url.Parse(to)
			if err != nil {
				return fmt.Errorf("parse 'to' URL %s: %w", to, err)
			}

			action, err := cmdutil.GetUserSetVarFromString(cmd, actionFlagName,
				actionEnvKey, false)
			if err != nil {
				return err
			}

			maxRetry := defaultMaxRetry

			maxRetryString := cmdutil.GetUserSetOptionalVarFromString(cmd, maxRetryFlagName,
				maxRetryEnvKey)

			if maxRetryString != "" {
				maxRetry, err = strconv.Atoi(maxRetryString)
				if err != nil {
					return fmt.Errorf("failed to convert max retry string to an integer: %w", err)
				}
			}

			waitTime, err := common.GetDuration(cmd, waitTimeFlagName,
				waitTimeEnvKey, defaultWaitTime)
			if err != nil {
				return err
			}

			var followIRI *url.URL

			if action == undoAction {
				followID, errGet := cmdutil.GetUserSetVarFromString(cmd, followIDFlagName,
					followIDEnvKey, false)
				if errGet != nil {
					return errGet
				}

				followIRI, err = url.Parse(followID)
				if err != nil {
					return fmt.Errorf("parse 'followID' URL %s: %w", followID, err)
				}
			}

			apClient, err := common.NewActivityPubClient(cmd)
			if err != nil {
				return fmt.Errorf("create ActivityPub client: %w", err)
			}

			actor, err := apClient.ResolveActor(actorIRI)
			if err != nil {
				return fmt.Errorf("discover 'actor' at %s: %w", actorIRI, err)
			}

			toActor, err := apClient.ResolveActor(to)
			if err != nil {
				return fmt.Errorf("discover 'to' actor %s: %w", to, err)
			}

			var reqBytes []byte

			switch action {
			case followAction:
				req := vocab.NewFollowActivity(
					vocab.NewObjectProperty(vocab.WithIRI(toActor.ID().URL())),
					vocab.WithActor(actor.ID().URL()),
					vocab.WithTo(toIRI),
				)

				reqBytes, err = json.Marshal(req)
				if err != nil {
					return fmt.Errorf("marshal follow activity: %w", err)
				}
			case undoAction:
				undo := vocab.NewUndoActivity(
					vocab.NewObjectProperty(vocab.WithActivity(
						vocab.NewFollowActivity(
							vocab.NewObjectProperty(vocab.WithIRI(toActor.ID().URL())),
							vocab.WithID(followIRI),
							vocab.WithActor(actor.ID().URL()),
						),
					)),
					vocab.WithActor(actor.ID().URL()),
					vocab.WithTo(toIRI),
				)

				reqBytes, err = json.Marshal(undo)
				if err != nil {
					return fmt.Errorf("marshal undo activity: %w", err)
				}
			default:
				return fmt.Errorf("action %s not supported", action)
			}

			result, err := common.SendRequest(httpClient, reqBytes, headers, http.MethodPost, outboxURL)
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			for i := 1; i <= maxRetry; i++ {
				exists, err := apClient.CollectionContains(actor.Following(), toActor.ID().String())
				if err != nil {
					return err
				}

				if (action == undoAction && !exists) || (action == followAction && exists) {
					break
				}

				if i == maxRetry {
					return fmt.Errorf("%s failed max retries exhausted check server logs for more info", action)
				}

				time.Sleep(waitTime)
			}

			fmt.Printf("success %s id: %s\n", action, result)

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	common.AddCommonFlags(startCmd)

	startCmd.Flags().StringP(outboxURLFlagName, "", "", outboxURLFlagUsage)
	startCmd.Flags().StringP(actorFlagName, "", "", actorFlagUsage)
	startCmd.Flags().StringP(toFlagName, "", "", toFlagUsage)
	startCmd.Flags().StringP(actionFlagName, "", "", actionFlagUsage)
	startCmd.Flags().StringP(followIDFlagName, "", "", followIDFlagUsage)
	startCmd.Flags().StringP(maxRetryFlagName, "", "", maxRetryFlagUsage)
	startCmd.Flags().StringP(waitTimeFlagName, "", "", waitTimeFlagUsage)
}
