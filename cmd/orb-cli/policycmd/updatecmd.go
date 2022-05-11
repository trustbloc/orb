/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policycmd

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
		Short: "Updates the witness policy.",
		Long: `Updates the witness policy. For example: policy update ` +
			`--policy "MinPercent(100,batch) AND OutOf(1,system)" --url https://orb.domain1.com/policy`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeUpdate(cmd *cobra.Command) error {
	u, policy, err := getUpdateArgs(cmd)
	if err != nil {
		return err
	}

	_, err = common.SendHTTPRequest(cmd, []byte(policy), http.MethodPost, u)
	if err != nil {
		return err
	}

	fmt.Println("Witness policy has successfully been updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringP(policyFlagName, "", "", policyFlagUsage)
}

func getUpdateArgs(cmd *cobra.Command) (u, policy string, err error) {
	u, err = cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return "", "", err
	}

	_, err = url.Parse(u)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL %s: %w", u, err)
	}

	policy, err = cmdutils.GetUserSetVarFromString(cmd, policyFlagName, typeEnvKey, false)
	if err != nil {
		return "", "", err
	}

	return u, policy, nil
}
