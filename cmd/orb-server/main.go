/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main Orb.
//
// Terms Of Service:
//
//     Schemes: http
//     Version: 1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
// swagger:meta
package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/logutil-go/pkg/log"

	"github.com/trustbloc/orb/cmd/orb-server/startcmd"
)

var logger = log.New("orb-server")

func main() {
	rootCmd := &cobra.Command{
		Use: "orb-server",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal("Failed to run Orb server.", log.WithError(err))
	}
}
