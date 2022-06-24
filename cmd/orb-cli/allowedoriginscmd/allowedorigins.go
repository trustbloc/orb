/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginscmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	urlFlagName  = "url"
	urlFlagUsage = "The URL of the allowed origins REST endpoint." +
		" Alternatively, this can be set with the following environment variable: " + urlEnvKey
	urlEnvKey = "ORB_CLI_URL"

	originFlagName  = "anchororigin"
	originFlagUsage = "The URI to add to/remove from the allowed anchor origins list. Multiple URIs may be specified," +
		" for example, --anchororigin <uri1> --anchororigin <uri2>." +
		" Alternatively, this can be set with the following environment variable as a comma-separated list of URIs: " +
		originsEnvKey
	originsEnvKey = "ORB_CLI_ANCHOR_ORIGINS"
)

// GetCmd returns the Cobra acceptlist command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "allowedorigins",
		Short:        "Manages allowed anchor origins.",
		SilenceUsage: true,
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
