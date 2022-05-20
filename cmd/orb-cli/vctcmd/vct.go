/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vctcmd

import (
	"errors"

	"github.com/spf13/cobra"
)

const (
	casURLFlagName  = "cas-url"
	casURLEnvKey    = "ORB_CAS_URL"
	casURLFlagUsage = "The URL of the CAS endpoint. If not specified then IPFS is assumed." +
		" Alternatively, this can be set with the following environment variable: " + casURLEnvKey

	anchorHashFlagName  = "anchor"
	anchorHashEnvKey    = "ORB_CLI_ANCHOR"
	anchorHashFlagUsage = `The hash of the anchor linkset.` +
		" Alternatively, this can be set with the following environment variable: " + anchorHashEnvKey

	verboseFlagName  = "verbose"
	verboseEnvKey    = "ORB_CLI_VERBOSE"
	verboseFlagUsage = `Sets verbose mode, i.e. additional information is output..` +
		" Alternatively, this can be set with the following environment variable: " + verboseEnvKey

	vctAuthTokenFlagName  = "vct-auth-token" //nolint:gosec
	vctAuthTokenFlagUsage = "VCT auth token." +
		" Alternatively, this can be set with the following environment variable: " + vctAuthTokenEnvKey
	vctAuthTokenEnvKey = "ORB_CLI_VCT_AUTH_TOKEN" //nolint:gosec
)

// GetCmd returns the Cobra policy command.
func GetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "vct",
		Short:        "Examines the VCT log.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("expecting subcommand: verify")
		},
	}

	cmd.AddCommand(
		newVerifyCmd(&clientProvider{}),
	)

	return cmd
}
