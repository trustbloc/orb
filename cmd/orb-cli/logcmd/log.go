/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logcmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	urlFlagName  = "url"
	urlEnvKey    = "ORB_CLI_URL"
	urlFlagUsage = "The URL of the log REST endpoint." +
		" Alternatively, this can be set with the following environment variable: " + urlEnvKey

	logFlagName  = "log"
	typeEnvKey   = "ORB_CLI_LOG"
	logFlagUsage = `The domain log. For example "https://vct.com/log".` +
		" Alternatively, this can be set with the following environment variable: " + typeEnvKey
)

// GetCmd returns the Cobra log command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "log",
		Short:        "Manages the domain log.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expecting subcommand update or get")
		},
	}

	cmd.AddCommand(
		newUpdateCmd(),
		newGetCmd(),
	)

	return cmd
}
