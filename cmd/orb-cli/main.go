/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/cmd/orb-cli/createdidcmd"
)

var logger = log.New("orb-cli")

func main() {
	rootCmd := &cobra.Command{
		Use: "orb-cli",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	didCmd := &cobra.Command{
		Use: "did",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	didCmd.AddCommand(createdidcmd.GetCreateDIDCmd())

	rootCmd.AddCommand(didCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run orb-cli: %s", err.Error())
	}
}
