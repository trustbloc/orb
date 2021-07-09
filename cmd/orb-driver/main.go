/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/cmd/orb-driver/startcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "orb driver",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run rp: %s", err.Error())
	}
}
