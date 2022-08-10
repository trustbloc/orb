/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package witnesscmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
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
	actionFlagUsage = "Witness action (InviteWitness, Undo)." +
		" Alternatively, this can be set with the following environment variable: " + actionEnvKey
	actionEnvKey = "ORB_CLI_ACTION"

	inviteWitnessFlagName  = "invite-witness-id"
	inviteWitnessFlagUsage = "Invite witness id required for undo action." +
		" Alternatively, this can be set with the following environment variable: " + inviteWitnessEnvKey
	inviteWitnessEnvKey = "ORB_CLI_INVITE_WITNESS_ID"

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
	inviteWitnessAction = "InviteWitness"
	undoAction          = "Undo"
	defaultMaxRetry     = 10
	defaultWaitTime     = 1 * time.Second
)

// GetCmd returns the Cobra witness command.
func GetCmd() *cobra.Command {
	cmd := cmd()

	createFlags(cmd)

	return cmd
}

func cmd() *cobra.Command { //nolint:funlen,gocyclo,cyclop,gocognit
	return &cobra.Command{
		Use:          "witness",
		Short:        "manage witness",
		Long:         "manage witness ",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			httpClient, err := common.NewHTTPClient(cmd)

			authToken := cmdutils.GetUserSetOptionalVarFromString(cmd, common.AuthTokenFlagName,
				common.AuthTokenEnvKey)
			if err != nil {
				return err
			}

			headers := make(map[string]string)
			if authToken != "" {
				headers["Authorization"] = "Bearer " + authToken
			}

			outboxURL, err := cmdutils.GetUserSetVarFromString(cmd, outboxURLFlagName,
				outboxURLEnvKey, false)
			if err != nil {
				return err
			}

			actorIRI, err := cmdutils.GetUserSetVarFromString(cmd, actorFlagName,
				actorEnvKey, false)
			if err != nil {
				return err
			}

			to, err := cmdutils.GetUserSetVarFromString(cmd, toFlagName,
				toEnvKey, false)
			if err != nil {
				return err
			}

			toIRI, err := url.Parse(to)
			if err != nil {
				return fmt.Errorf("parse 'to' URL %s: %w", to, err)
			}

			action, err := cmdutils.GetUserSetVarFromString(cmd, actionFlagName,
				actionEnvKey, false)
			if err != nil {
				return err
			}

			maxRetry := defaultMaxRetry

			maxRetryString := cmdutils.GetUserSetOptionalVarFromString(cmd, maxRetryFlagName,
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

			var inviteWitnessIRI *url.URL

			if action == undoAction {
				inviteWitness, errGet := cmdutils.GetUserSetVarFromString(cmd, inviteWitnessFlagName,
					inviteWitnessEnvKey, false)
				if errGet != nil {
					return errGet
				}

				inviteWitnessIRI, err = url.Parse(inviteWitness)
				if err != nil {
					return fmt.Errorf("parse 'witnessID' URL %s: %w", inviteWitness, err)
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
			case inviteWitnessAction:
				req := vocab.NewInviteActivity(
					vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
					vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(toActor.ID().URL()))),
					vocab.WithActor(actor.ID().URL()),
					vocab.WithTo(toIRI),
				)

				reqBytes, err = json.Marshal(req)
				if err != nil {
					return err
				}

			case undoAction:
				undo := vocab.NewUndoActivity(
					vocab.NewObjectProperty(vocab.WithActivity(
						vocab.NewInviteActivity(
							vocab.NewObjectProperty(vocab.WithIRI(vocab.AnchorWitnessTargetIRI)),
							vocab.WithID(inviteWitnessIRI),
							vocab.WithTarget(vocab.NewObjectProperty(vocab.WithIRI(toActor.ID().URL()))),
							vocab.WithActor(actor.ID().URL()),
						),
					)),
					vocab.WithActor(actor.ID().URL()),
					vocab.WithTo(toIRI),
				)

				reqBytes, err = json.Marshal(undo)
				if err != nil {
					return err
				}

			default:
				return fmt.Errorf("action %s not supported", action)
			}

			result, err := common.SendRequest(httpClient, reqBytes, headers, http.MethodPost, outboxURL)
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			for i := 1; i <= maxRetry; i++ {
				exists, err := apClient.CollectionContains(actor.Witnesses(), toActor.ID().String())
				if err != nil {
					return err
				}

				if (action == undoAction && !exists) || (action == inviteWitnessAction && exists) {
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
	startCmd.Flags().StringP(inviteWitnessFlagName, "", "", inviteWitnessFlagUsage)
	startCmd.Flags().StringP(maxRetryFlagName, "", "", maxRetryFlagUsage)
	startCmd.Flags().StringP(waitTimeFlagName, "", "", waitTimeFlagUsage)
}
