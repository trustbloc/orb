/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logcmd

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
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

func executeUpdate(cmd *cobra.Command) error { //nolint: gocyclo,cyclop
	u, err := cmdutil.GetUserSetVarFromString(cmd, urlFlagName, urlEnvKey, false)
	if err != nil {
		return err
	}

	_, err = url.Parse(u)
	if err != nil {
		return fmt.Errorf("invalid URL %s: %w", u, err)
	}

	log, err := cmdutil.GetUserSetVarFromString(cmd, logFlagName, typeEnvKey, false)
	if err != nil {
		return err
	}

	maxRetry := defaultMaxRetry

	maxRetryString := cmdutil.GetUserSetOptionalVarFromString(cmd, maxRetryFlagName,
		maxRetryEnvKey)

	if maxRetryString != "" {
		maxRetry, err = strconv.Atoi(maxRetryString)
		if err != nil {
			return fmt.Errorf("failed to convert max retry string to an integer: %w", err)
		}
	}

	waitTime, err := common.GetDuration(cmd, waitTimeFlagName,
		waitTimeEnvKey, defaultWaitTime)
	if err != nil {
		return err
	}

	for i := 1; i <= maxRetry; i++ {
		_, err = common.SendHTTPRequest(cmd, []byte(log), http.MethodPost, u)
		if err != nil {
			return err
		}

		resp, err := common.SendHTTPRequest(cmd, nil, http.MethodGet, u)
		if err != nil {
			return err
		}

		if string(resp) == log {
			break
		}

		if i == maxRetry {
			return fmt.Errorf("update log failed max retries exhausted check server logs for more info")
		}

		time.Sleep(waitTime)
	}

	fmt.Println("Domain log has successfully been updated.")

	return nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(urlFlagName, "", "", urlFlagUsage)
	cmd.Flags().StringP(logFlagName, "", "", logFlagUsage)
	cmd.Flags().StringP(maxRetryFlagName, "", "", maxRetryFlagUsage)
	cmd.Flags().StringP(waitTimeFlagName, "", "", waitTimeFlagUsage)
}
