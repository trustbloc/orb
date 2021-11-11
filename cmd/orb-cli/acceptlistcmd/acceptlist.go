/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acceptlistcmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	urlFlagName  = "url"
	urlFlagUsage = "The URL of the accept list REST endpoint." +
		" Alternatively, this can be set with the following environment variable: " + urlEnvKey
	urlEnvKey = "ORB_CLI_URL"

	actorFlagName  = "actor"
	actorFlagUsage = "A comma-separated list of service URIs to add to/remove from the accept list." +
		" Alternatively, this can be set with the following environment variable: " + actorEnvKey
	actorEnvKey = "ORB_CLI_ACTOR"

	typeFlagName  = "type"
	typeFlagUsage = "Accept list type (follow or invite-witness)." +
		" Alternatively, this can be set with the following environment variable: " + typeEnvKey
	typeEnvKey = "ORB_CLI_ACCEPT_TYPE"
)

// GetCmd returns the Cobra acceptlist command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acceptlist",
		Short: "Manages accept lists.",
		Long:  "Manages accept lists for 'Follow' and 'Invite' witness authorization handlers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expecting subcommand add, remove, or get")
		},
	}

	cmd.AddCommand(
		newAddCmd(),
		newRemoveCmd(),
		newGetCmd(),
	)

	return cmd
}
