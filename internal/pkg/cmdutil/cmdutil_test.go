/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmdutil_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
)

const (
	flagName = "host-url"
	envKey   = "TEST_HOST_URL"
)

func TestGetUserSetVarFromStringNegative(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := cmdutil.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	t.Setenv(envKey, "")

	env, err = cmdutil.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	command.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, ""}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	env, err = cmdutil.GetUserSetVarFromString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromArrayStringNegative(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := cmdutil.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	t.Setenv(envKey, "")

	env, err = cmdutil.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	command.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, ""}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	env, err = cmdutil.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromString(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	t.Setenv(envKey, hostURL)

	// test resolution via environment variable
	env, err := cmdutil.GetUserSetVarFromString(command, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, hostURL, env)

	// set command line arguments
	command.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, "other"}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = cmdutil.GetUserSetVarFromString(command, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, "other", env)

	env = cmdutil.GetUserSetOptionalVarFromString(command, flagName, "")
	require.Equal(t, "other", env)
}

func TestGetUserSetVarFromArrayString(t *testing.T) {
	os.Clearenv()

	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	t.Setenv(envKey, hostURL)

	// test resolution via environment variable
	env, err := cmdutil.GetUserSetVarFromArrayString(command, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, []string{hostURL}, env)

	// set command line arguments
	command.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, "other", "--" + flagName, "other1"}
	command.SetArgs(args)
	err = command.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = cmdutil.GetUserSetVarFromArrayString(command, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, []string{"other", "other1"}, env)

	env = cmdutil.GetUserSetOptionalVarFromArrayString(command, flagName, "")
	require.Equal(t, []string{"other", "other1"}, env)
}

func TestGetBool(t *testing.T) {
	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	t.Run("test unset value should use defaultValue", func(t *testing.T) {
		env, err := cmdutil.GetBool(command, flagName, envKey, false)
		require.NoError(t, err)
		require.False(t, env)
	})

	t.Run("test env var is set", func(t *testing.T) {
		someIntVal := true
		t.Setenv(envKey, fmt.Sprint(someIntVal))

		// test resolution via environment variable
		env, err := cmdutil.GetBool(command, flagName, envKey, true)
		require.NoError(t, err)
		require.Equal(t, someIntVal, env)
	})

	t.Run("test invalid env var", func(t *testing.T) {
		t.Setenv(envKey, "not-an-int")

		env, err := cmdutil.GetBool(command, flagName, envKey, true)
		require.Error(t, err)
		require.Empty(t, env)
	})
}

func TestGetDuration(t *testing.T) {
	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	defaultDuration := 10 * time.Second

	t.Run("test unset value should use defaultValue", func(t *testing.T) {
		env, err := cmdutil.GetDuration(command, flagName, envKey, defaultDuration)
		require.NoError(t, err)
		require.Equal(t, defaultDuration, env)
	})

	t.Run("test env var is set", func(t *testing.T) {
		duration := 15 * time.Second
		t.Setenv(envKey, duration.String())

		// test resolution via environment variable
		env, err := cmdutil.GetDuration(command, flagName, envKey, defaultDuration)
		require.NoError(t, err)
		require.Equal(t, duration, env)
	})

	t.Run("test invalid env var", func(t *testing.T) {
		t.Setenv(envKey, "not-an-int")

		env, err := cmdutil.GetDuration(command, flagName, envKey, defaultDuration)
		require.Error(t, err)
		require.Less(t, env, 0*time.Second)
	})
}

func TestGetInt(t *testing.T) {
	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	t.Run("test unset value should use defaultValue", func(t *testing.T) {
		env, err := cmdutil.GetInt(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, 0, env)
	})

	t.Run("test env var is set", func(t *testing.T) {
		someIntVal := 15
		t.Setenv(envKey, fmt.Sprint(someIntVal))

		// test resolution via environment variable
		env, err := cmdutil.GetInt(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, someIntVal, env)
	})

	t.Run("test invalid env var", func(t *testing.T) {
		t.Setenv(envKey, "not-an-int")

		env, err := cmdutil.GetInt(command, flagName, envKey, 0)
		require.Error(t, err)
		require.Empty(t, env)
	})
}

func TestGetUInt64(t *testing.T) {
	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	t.Run("test unset value should use defaultValue", func(t *testing.T) {
		env, err := cmdutil.GetUInt64(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, uint64(0), env)
	})

	t.Run("test env var is set", func(t *testing.T) {
		someIntVal := uint64(15)
		t.Setenv(envKey, fmt.Sprint(someIntVal))

		// test resolution via environment variable
		env, err := cmdutil.GetUInt64(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, someIntVal, env)
	})

	t.Run("test invalid env var", func(t *testing.T) {
		t.Setenv(envKey, "not-an-int")

		env, err := cmdutil.GetUInt64(command, flagName, envKey, 0)
		require.Error(t, err)
		require.Empty(t, env)
	})
}

func TestGetFloat(t *testing.T) {
	command := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	t.Run("test unset value should use defaultValue", func(t *testing.T) {
		env, err := cmdutil.GetFloat(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, 0.0, env)
	})

	t.Run("test env var is set", func(t *testing.T) {
		someIntVal := 15.0
		t.Setenv(envKey, fmt.Sprint(someIntVal))

		// test resolution via environment variable
		env, err := cmdutil.GetFloat(command, flagName, envKey, 0)
		require.NoError(t, err)
		require.Equal(t, someIntVal, env)
	})

	t.Run("test invalid env var", func(t *testing.T) {
		t.Setenv(envKey, "not-an-int")

		env, err := cmdutil.GetFloat(command, flagName, envKey, 0)
		require.Error(t, err)
		require.Empty(t, env)
	})
}
