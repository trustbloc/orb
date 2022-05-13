/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logcmd

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

func newUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Updates the domain log.",
		Long: `Updates the domain log. For example: log update ` +
			`--url https://orb.domain1.com/log --log https://vct.com/log`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeUpdate(cmd *cobra.Command) error {
	u, log, err := getUpdateArgs(cmd)
	if err != nil {
		return err
	}

	_, err = common.SendHTTPRequest(cmd, []byte(log), http.MethodPost, u)
	if err != nil {
		return err
	}

	fmt.Println("Domain log has successfully been updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringP(logFlagName, "", "", logFlagUsage)
}

func getUpdateArgs(cmd *cobra.Command) (u, log string, err error) {
	u, err = cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return "", "", err
	}

	_, err = url.Parse(u)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL %s: %w", u, err)
	}

	log, err = cmdutils.GetUserSetVarFromString(cmd, logFlagName, typeEnvKey, false)
	if err != nil {
		return "", "", err
	}

	return u, log, nil
}
