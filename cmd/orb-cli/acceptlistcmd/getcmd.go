/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acceptlistcmd

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
		Short:        "Retrieves accept lists.",
		Long:         "Retrieves accept lists used by the 'Follow' and 'Invite' witness authorization handlers.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeGet(cmd)
		},
	}

	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringP(typeFlagName, "", "", typeFlagUsage)

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

	acceptType, err := cmdutils.GetUserSetVarFromString(cmd, typeFlagName, typeEnvKey, true)
	if err != nil {
		return err
	}

	if acceptType != "" {
		u = fmt.Sprintf("%s?type=%s", u, acceptType)
	}

	resp, err := common.SendHTTPRequest(cmd, nil, http.MethodGet, u)
	if err != nil {
		return err
	}

	fmt.Println(string(resp))

	return nil
}
