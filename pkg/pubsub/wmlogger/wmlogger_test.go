/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wmlogger

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/pubsub/wmlogger/mocks"
)

//go:generate counterfeiter -o ./mocks/logger.gen.go --fake-name Logger . logger

func TestNew(t *testing.T) {
	logger := New()
	require.NotNil(t, logger)
}

func TestWMLogger(t *testing.T) {
	v2, e := url.Parse("https://example.com")
	require.NoError(t, e)

	fields := watermill.LogFields{"field1": "value1", "field2": v2}

	err := fmt.Errorf("some error")

	t.Run("Debug level", func(t *testing.T) {
		log.SetLevel(Module, log.DEBUG)

		l := &mocks.Logger{}

		logger := newWMLogger(l)
		require.NotNil(t, logger)

		logger.Error("message", err, fields)
		logger.Info("message", fields)
		logger.Debug("message", fields)
		logger.Trace("message", nil)

		require.Equal(t, 1, l.ErrorCallCount())
		require.Equal(t, 1, l.InfoCallCount())
		require.Equal(t, 2, l.DebugCallCount())
	})

	t.Run("Info level", func(t *testing.T) {
		log.SetLevel(Module, log.INFO)

		l := &mocks.Logger{}

		logger := newWMLogger(l)
		require.NotNil(t, logger)

		logger.Error("message", err, fields)
		logger.Info("message", fields)
		logger.Debug("message", fields)
		logger.Trace("message", nil)

		require.Equal(t, 1, l.ErrorCallCount())
		require.Equal(t, 1, l.InfoCallCount())
		require.Equal(t, 0, l.DebugCallCount())
	})

	t.Run("Warn level", func(t *testing.T) {
		log.SetLevel(Module, log.WARNING)

		l := &mocks.Logger{}

		logger := newWMLogger(l)
		require.NotNil(t, logger)

		logger.Error("message", err, fields)
		logger.Info("message", fields)
		logger.Debug("message", fields)
		logger.Trace("message", nil)

		require.Equal(t, 1, l.ErrorCallCount())
		require.Equal(t, 0, l.InfoCallCount())
		require.Equal(t, 0, l.DebugCallCount())
	})

	t.Run("Error level", func(t *testing.T) {
		log.SetLevel(Module, log.ERROR)

		l := &mocks.Logger{}

		logger := newWMLogger(l)
		require.NotNil(t, logger)

		logger.Error("message", err, fields)
		logger.Info("message", fields)
		logger.Debug("message", fields)
		logger.Trace("message", nil)

		require.Equal(t, 1, l.ErrorCallCount())
		require.Equal(t, 0, l.InfoCallCount())
		require.Equal(t, 0, l.DebugCallCount())
	})

	t.Run("With", func(t *testing.T) {
		log.SetLevel(Module, log.DEBUG)

		l := &mocks.Logger{}

		logger := newWMLogger(l).With(watermill.LogFields{"field3": "value3"})
		require.NotNil(t, logger)

		logger.Debug("message", fields)

		require.Equal(t, 1, l.DebugCallCount())
	})
}
