/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acceptlistcmd

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
		Use:   "add",
		Short: "Adds actors to an accept list.",
		Long:  "Adds actors to an accept list used by the 'Follow' and 'Invite' witness authorization handlers.",
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
		Short: "Removes actors from an accept list.",
		Long:  "Removes actors from an accept list used by the 'Follow' and 'Invite' witness authorization handlers.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd, false)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeUpdate(cmd *cobra.Command, isAdd bool) error {
	u, acceptType, actors, err := getUpdateArgs(cmd)
	if err != nil {
		return err
	}

	req := acceptListRequest{
		Type: acceptType,
	}

	if isAdd {
		req.Add = actors
	} else {
		req.Remove = actors
	}

	reqBytes, err := json.Marshal([]acceptListRequest{req})
	if err != nil {
		return err
	}

	_, err = common.SendHTTPRequest(cmd, reqBytes, http.MethodPost, u)
	if err != nil {
		return err
	}

	fmt.Println("Accept list has successfully been updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringArrayP(actorFlagName, "", nil, actorFlagUsage)
	cmd.Flags().StringP(typeFlagName, "", "", typeFlagUsage)
}

func getUpdateArgs(cmd *cobra.Command) (u, acceptType string, actors []string, err error) {
	u, err = cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return "", "", nil, err
	}

	_, err = url.Parse(u)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid URL %s: %w", u, err)
	}

	acceptType, err = cmdutils.GetUserSetVarFromString(cmd, typeFlagName, typeEnvKey, false)
	if err != nil {
		return "", "", nil, err
	}

	actors, err = cmdutils.GetUserSetVarFromArrayString(cmd, actorFlagName, actorEnvKey, false)
	if err != nil {
		return "", "", nil, err
	}

	for _, actor := range actors {
		_, err = url.Parse(actor)
		if err != nil {
			return "", "", nil, fmt.Errorf("invalid actor URL %s: %w", u, err)
		}
	}

	return u, acceptType, actors, nil
}

type acceptListRequest struct {
	Type   string   `json:"type"`
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}
