/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/cmd/orb-cli/createdidcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/deactivatedidcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/followcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/ipfskeygencmd"
	"github.com/trustbloc/orb/cmd/orb-cli/ipnshostmetagencmd"
	"github.com/trustbloc/orb/cmd/orb-cli/ipnshostmetauploadcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/recoverdidcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/updatedidcmd"
	"github.com/trustbloc/orb/cmd/orb-cli/witnesscmd"
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

	ipfsCmd := &cobra.Command{
		Use: "ipfs",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	ipfsCmd.AddCommand(ipfskeygencmd.GetCmd())
	ipfsCmd.AddCommand(ipnshostmetagencmd.GetCmd())
	ipfsCmd.AddCommand(ipnshostmetauploadcmd.GetCmd())

	didCmd.AddCommand(createdidcmd.GetCreateDIDCmd())
	didCmd.AddCommand(updatedidcmd.GetUpdateDIDCmd())
	didCmd.AddCommand(recoverdidcmd.GetRecoverDIDCmd())
	didCmd.AddCommand(deactivatedidcmd.GetDeactivateDIDCmd())

	rootCmd.AddCommand(didCmd)
	rootCmd.AddCommand(ipfsCmd)
	rootCmd.AddCommand(followcmd.GetCmd())
	rootCmd.AddCommand(witnesscmd.GetCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run orb-cli: %s", err.Error())
	}
}
