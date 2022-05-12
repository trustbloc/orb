/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitorcmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	urlFlagName  = "url"
	urlFlagUsage = "The URL of the log monitor REST endpoint." +
		" Alternatively, this can be set with the following environment variable: " + urlEnvKey
	urlEnvKey = "ORB_CLI_URL"

	logFlagName   = "log"
	logsFlagUsage = "A comma-separated list of log URIs to activate/deactivate." +
		" Alternatively, this can be set with the following environment variable: " + logsEnvKey
	logsEnvKey = "ORB_CLI_LOG"

	statusFlagName  = "status"
	statusFlagUsage = "Filter by log status for log monitor active/inactive list." +
		" Alternatively, this can be set with the following environment variable: " + statusEnvKey
	statusEnvKey = "ORB_CLI_STATUS"
)

// GetCmd returns the Cobra logmonitor command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "logmonitor",
		Short:        "Manages activating/deactivating logs for monitoring.",
		Long:         "Manages activating/deactivating logs for monitoring.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expecting subcommand activate, deactivate, or get")
		},
	}

	cmd.AddCommand(
		newActivateCmd(),
		newDeactivateCmd(),
		newGetCmd(),
	)

	return cmd
}
