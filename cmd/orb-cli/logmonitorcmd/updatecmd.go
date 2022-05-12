/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitorcmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

func newActivateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "activate",
		Short:        "Adds log to the list of logs to be monitored.",
		Long:         "Adds log to the list of logs to be monitored.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd, true)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func newDeactivateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deactivate",
		Short: "Removes log from the list of monitored (active) logs.",
		Long:  "Removes log from the list of monitored (active) logs.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeUpdate(cmd, false)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeUpdate(cmd *cobra.Command, isActivate bool) error {
	u, logs, err := getUpdateArgs(cmd)
	if err != nil {
		return err
	}

	req := logRequest{}

	if isActivate {
		req.Activate = logs
	} else {
		req.Deactivate = logs
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = common.SendHTTPRequest(cmd, reqBytes, http.MethodPost, u)
	if err != nil {
		return err
	}

	fmt.Println("logs successfully updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringArrayP(logFlagName, "", nil, logsFlagUsage)
}

func getUpdateArgs(cmd *cobra.Command) (u string, logs []string, err error) {
	u, err = cmdutils.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return "", nil, err
	}

	_, err = url.Parse(u)
	if err != nil {
		return "", nil, fmt.Errorf("invalid URL %s: %w", u, err)
	}

	logs, err = cmdutils.GetUserSetVarFromArrayString(cmd, logFlagName, logsEnvKey, false)
	if err != nil {
		return "", nil, err
	}

	for _, log := range logs {
		_, err = url.Parse(log)
		if err != nil {
			return "", nil, fmt.Errorf("invalid log URL %s: %w", u, err)
		}
	}

	return u, logs, nil
}

type logRequest struct {
	Activate   []string `json:"activate"`
	Deactivate []string `json:"deactivate"`
}
