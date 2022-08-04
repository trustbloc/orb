/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logcmd

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultMaxRetry = 10
	defaultWaitTime = 1 * time.Second
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

	maxRetryFlagName  = "max-retry"
	maxRetryEnvKey    = "ORB_CLI_MAX_RETRY"
	maxRetryFlagUsage = "max retry to check if follow cmd is succeed default value is 10" +
		" Alternatively, this can be set with the following environment variable: " + maxRetryEnvKey

	waitTimeFlagName  = "wait-time"
	waitTimeEnvKey    = "ORB_CLI_WAIT_TIME"
	waitTimeFlagUsage = "wait time between retries default value is 1s" +
		" Alternatively, this can be set with the following environment variable: " + waitTimeEnvKey
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
