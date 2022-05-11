/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policycmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	urlFlagName  = "url"
	urlEnvKey    = "ORB_CLI_URL"
	urlFlagUsage = "The URL of the witness policy REST endpoint." +
		" Alternatively, this can be set with the following environment variable: " + urlEnvKey

	policyFlagName  = "policy"
	typeEnvKey      = "ORB_CLI_POLICY"
	policyFlagUsage = `The witness policy. For example "MinPercent(100,batch) AND OutOf(1,system)".` +
		" Alternatively, this can be set with the following environment variable: " + typeEnvKey
)

// GetCmd returns the Cobra policy command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "policy",
		Short:        "Manages the witness policy.",
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
