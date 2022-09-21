/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginscmd

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
)

func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "get",
		Short:        "Retrieves allowed anchor origins.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeGet(cmd)
		},
	}

	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)

	return cmd
}

func executeGet(cmd *cobra.Command) error {
	u, err := cmdutil.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return err
	}

	_, err = url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL %s: %w", u, err)
	}

	resp, err := common.SendHTTPRequest(cmd, nil, http.MethodGet, u)
	if err != nil {
		return err
	}

	fmt.Println(string(resp))

	return nil
}
