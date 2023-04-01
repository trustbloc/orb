/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmdutil

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// GetUserSetOptionalVarFromString returns values either command line flag or environment variable.
func GetUserSetOptionalVarFromString(cmd *cobra.Command, flagName, envKey string) string {
	v, _ := GetUserSetVarFromString(cmd, flagName, envKey, true)

	return v
}

// GetUserSetVarFromString returns values either command line flag or environment variable.
func GetUserSetVarFromString(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if value == "" {
			return "", fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return "", fmt.Errorf("%s value is empty", envKey)
		}

		return value, nil
	}

	return "", errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

// GetUserSetOptionalVarFromArrayString returns values either command line flag or environment variable.
func GetUserSetOptionalVarFromArrayString(cmd *cobra.Command, flagName, envKey string) []string {
	v, _ := GetUserSetVarFromArrayString(cmd, flagName, envKey, true)

	return v
}

// GetUserSetVarFromArrayString returns values either command line flag or environment variable.
func GetUserSetVarFromArrayString(cmd *cobra.Command, flagName, envKey string, isOptional bool) ([]string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetStringArray(flagName)
		if err != nil {
			return nil, fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if len(value) == 0 {
			return nil, fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return nil, fmt.Errorf("%s value is empty", envKey)
		}

		if value == "" {
			return []string{}, nil
		}

		return strings.Split(value, ","), nil
	}

	return nil, errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

// GetBool returns values either command line flag or environment variable.
func GetBool(cmd *cobra.Command, flagName, envKey string, defaultValue bool) (bool, error) {
	str, err := GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return false, fmt.Errorf("%s: %w", flagName, err)
	}

	if str == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseBool(str)
	if err != nil {
		return false, fmt.Errorf("invalid value for %s [%s]: %w", flagName, str, err)
	}

	return value, nil
}

// GetDuration returns values either command line flag or environment variable.
func GetDuration(cmd *cobra.Command, flagName, envKey string, defaultDuration time.Duration) (time.Duration, error) {
	timeoutStr, err := GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return -1, fmt.Errorf("%s: %w", flagName, err)
	}

	if timeoutStr == "" {
		return defaultDuration, nil
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return -1, fmt.Errorf("invalid value for %s [%s]: %w", flagName, timeoutStr, err)
	}

	return timeout, nil
}

// GetInt returns values either command line flag or environment variable.
func GetInt(cmd *cobra.Command, flagName, envKey string, defaultValue int) (int, error) {
	str, err := GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", flagName, err)
	}

	if str == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s [%s]: %w", flagName, str, err)
	}

	return value, nil
}

// GetUInt64 returns values either command line flag or environment variable.
func GetUInt64(cmd *cobra.Command, flagName, envKey string, defaultValue uint64) (uint64, error) {
	str, err := GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", flagName, err)
	}

	if str == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s [%s]: %w", flagName, str, err)
	}

	return value, nil
}

// GetFloat returns values either command line flag or environment variable.
func GetFloat(cmd *cobra.Command, flagName, envKey string, defaultValue float64) (float64, error) {
	str, err := GetUserSetVarFromString(cmd, flagName, envKey, true)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", flagName, err)
	}

	if str == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s [%s]: %w", flagName, str, err)
	}

	return value, nil
}
