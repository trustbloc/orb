/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package taskmgr

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
)

// Logs to a string that can be read later and also (optionally) logs to another logger.
type stringLogger struct {
	// If passthroughLogger is set, then log statements will also be passed through here so they can also be
	// displayed in the console during the test.
	passthroughLogger logger
	log               string
	lock              sync.Mutex
}

func (s *stringLogger) Debugf(msg string, args ...interface{}) {
	if s.passthroughLogger != nil {
		s.passthroughLogger.Debugf(msg, args...)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Infof(msg string, args ...interface{}) {
	if s.passthroughLogger != nil {
		s.passthroughLogger.Infof(msg, args...)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Warnf(msg string, args ...interface{}) {
	if s.passthroughLogger != nil {
		s.passthroughLogger.Warnf(msg, args...)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Errorf(msg string, args ...interface{}) {
	if s.passthroughLogger != nil {
		s.passthroughLogger.Errorf(msg, args...)
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log += fmt.Sprintf(msg, args...)
}

func (s *stringLogger) Read() string {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.log
}

func TestService(t *testing.T) {
	t.Run("Success, using multiple running services to "+
		"simulate multiple Orb servers within a cluster. One fails part way through and the other "+
		"takes over", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, mongoDBProvider.Close())
		}()

		coordinationStore, err := mongoDBProvider.OpenStore("orb-config")
		require.NoError(t, err)

		taskMgr1, taskMgr2 := getTestExpiryServices(t, coordinationStore)

		taskMgr1.Start()

		// Wait a second so that we can ensure that task manager 1 gets the permit and assigns itself the responsibility
		// of running tasks. At the end of the test, we will be stopping task manager 1 and checking to
		// see that task manager 2 is able to take over.
		time.Sleep(time.Second)

		require.Contains(t, taskMgr1.logger.(*stringLogger).Read(), "Running test-task in task manager 1")
		require.NotContains(t, taskMgr2.logger.(*stringLogger).Read(), "Running test-task in task manager 2")

		taskMgr2.Start()

		// Wait for the task to run again in task manager 1.
		time.Sleep(2 * time.Second)

		// Stop task manager 1 and wait for task manager 2 to take over.
		taskMgr1.Stop()

		time.Sleep(3 * time.Second)

		require.Contains(t, taskMgr2.logger.(*stringLogger).Read(), "Running test-task in task manager 2")

		taskMgr2.Stop()
	})

	t.Run("Unexpected failure while getting the permit from the coordination store", func(t *testing.T) {
		coordinationStore := &mock.Store{
			ErrGet: errors.New("get error"),
		}

		taskMgr := New(coordinationStore, time.Millisecond)

		taskMgr.RegisterTask("test-task", time.Millisecond, time.Millisecond, func() {
			t.Logf("Running test-task")
		})

		logger := &stringLogger{}

		taskMgr.logger = logger

		taskMgr.Start()
		defer taskMgr.Stop()

		ensureLogContainsMessage(t, logger, "get permit from DB for task [test-task]: get error")
	})

	t.Run("Fail to unmarshal permit", func(t *testing.T) {
		coordinationStore := &mock.Store{
			GetReturn: []byte("not a valid expiredDataCleanupPermit"),
		}

		taskMgr := New(coordinationStore, time.Millisecond)

		taskMgr.RegisterTask("test-task", time.Millisecond, time.Millisecond, func() {
			t.Logf("Running test-task")
		})

		logger := &stringLogger{}

		taskMgr.logger = logger

		taskMgr.Start()
		defer taskMgr.Stop()

		ensureLogContainsMessage(t, logger,
			"unmarshal permit for task [test-task]: invalid character 'o' in literal null")
	})
}

// We return the started services so that the caller can call service.Stop on them when the test is done.
// service2's logger is returned, so it can be examined later on in the test.
func getTestExpiryServices(t *testing.T, coordinationStore storage.Store) (*Manager, *Manager) {
	t.Helper()

	taskMgr1 := New(coordinationStore, 500*time.Millisecond)

	service1LoggerModule := "expiry-service1"

	taskMgr1.logger = &stringLogger{
		passthroughLogger: log.New(service1LoggerModule),
	}

	log.SetLevel(service1LoggerModule, log.DEBUG)

	taskMgr1.RegisterTask("test-task", time.Second, 2*time.Second, func() {
		taskMgr1.logger.Infof("Running test-task in task manager 1")

		time.Sleep(time.Second)
	})

	taskMgr2 := New(coordinationStore, 500*time.Millisecond)

	service2LoggerModule := "expiry-service2"

	taskMgr2Logger := &stringLogger{
		passthroughLogger: log.New(service2LoggerModule),
	}

	taskMgr2.logger = taskMgr2Logger

	log.SetLevel(service2LoggerModule, log.DEBUG)

	taskMgr2.RegisterTask("test-task", time.Second, time.Second, func() {
		taskMgr2.logger.Infof("Running test-task in task manager 2")
	})

	return taskMgr1, taskMgr2
}

func ensureLogContainsMessage(t *testing.T, logger *stringLogger, expectedMessage string) {
	t.Helper()

	var logContents string

	var logContainsMessage bool

	for i := 0; i < 20; i++ {
		time.Sleep(time.Millisecond * 2)

		logContents = logger.Read()

		logContainsMessage = strings.Contains(logContents, expectedMessage)

		if logContainsMessage {
			break
		}
	}

	if !logContainsMessage {
		require.FailNow(t, "The log did not contain the expected message.",
			`Actual log contents: %s
Expected message: %s`, logContents, expectedMessage)
	}
}
