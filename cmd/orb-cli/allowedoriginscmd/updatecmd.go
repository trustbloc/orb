/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package allowedoriginscmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

func newAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "add",
		Short:        "Adds URIs to the allowed anchor origins list.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd, true)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Removes URIs to the allowed anchor origins list.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd, false)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeUpdate(cmd *cobra.Command, isAdd bool) error {
	u, uris, err := getUpdateArgs(cmd)
	if err != nil {
		return err
	}

	req := allowedOriginsRequest{}

	if isAdd {
		req.Add = uris
	} else {
		req.Remove = uris
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = common.SendHTTPRequest(cmd, reqBytes, http.MethodPost, u)
	if err != nil {
		return err
	}

	fmt.Println("Allowed anchor origins have been successfully updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringArrayP(originFlagName, "", nil, originFlagUsage)
}

func getUpdateArgs(cmd *cobra.Command) (u string, origins []string, err error) {
	u, err = cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return "", nil, err
	}

	_, err = url.Parse(u)
	if err != nil {
		return "", nil, fmt.Errorf("invalid URL %s: %w", u, err)
	}

	origins, err = cmdutils.GetUserSetVarFromArrayString(cmd, originFlagName, originsEnvKey, false)
	if err != nil {
		return "", nil, err
	}

	for _, origin := range origins {
		_, err = url.Parse(origin)
		if err != nil {
			return "", nil, fmt.Errorf("invalid anchor origin URI %s: %w", u, err)
		}
	}

	return u, origins, nil
}

type allowedOriginsRequest struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}
