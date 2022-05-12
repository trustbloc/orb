/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitorcmd

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "get",
		Short:        "Retrieves active/inactive log lists.",
		Long:         "Retrieves active/inactive log lists.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeGet(cmd)
		},
	}

	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringP(statusFlagName, "", "", statusFlagUsage)

	return cmd
}

func executeGet(cmd *cobra.Command) error {
	u, err := cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return err
	}

	_, err = url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL %s: %w", u, err)
	}

	status, err := cmdutils.GetUserSetVarFromString(cmd, statusFlagName, statusEnvKey, true)
	if err != nil {
		return err
	}

	if status != "" {
		u = fmt.Sprintf("%s?status=%s", u, status)
	}

	resp, err := common.SendHTTPRequest(cmd, nil, http.MethodGet, u)
	if err != nil {
		return err
	}

	fmt.Println(string(resp))

	return nil
}
