/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package taskmgr

import (
	"errors"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
)

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

		taskMgr2.Start()

		// Wait for the task to run again in task manager 1.
		time.Sleep(2 * time.Second)

		// Stop task manager 1 and wait for task manager 2 to take over.
		taskMgr1.Stop()

		time.Sleep(3 * time.Second)

		taskMgr2.Stop()
	})

	t.Run("Unexpected failure while getting the permit from the coordination store", func(t *testing.T) {
		coordinationStore := &mock.Store{
			ErrGet: errors.New("get error"),
		}

		taskMgr := New(coordinationStore, time.Millisecond)

		err := taskMgr.run(&registration{
			handle:   func() {},
			id:       "test-task",
			interval: time.Millisecond,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get permit from DB for task [test-task]: get error")
	})

	t.Run("Fail to unmarshal permit", func(t *testing.T) {
		coordinationStore := &mock.Store{
			GetReturn: []byte("not a valid expiredDataCleanupPermit"),
		}

		taskMgr := New(coordinationStore, time.Millisecond)

		err := taskMgr.run(&registration{
			handle:   func() {},
			id:       "test-task",
			interval: time.Millisecond,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"unmarshal permit for task [test-task]: invalid character 'o' in literal null")
	})
}

// We return the started services so that the caller can call service.Stop on them when the test is done.
// service2's logger is returned, so it can be examined later on in the test.
func getTestExpiryServices(t *testing.T, coordinationStore storage.Store) (*Manager, *Manager) {
	t.Helper()

	taskMgr1 := New(coordinationStore, 500*time.Millisecond)

	service1LoggerModule := "expiry-service1"

	log.SetLevel(service1LoggerModule, log.DEBUG)

	taskMgr1.RegisterTask("test-task", time.Second, func() {
		time.Sleep(time.Second)
	})

	taskMgr2 := New(coordinationStore, 500*time.Millisecond)

	taskMgr2.RegisterTask("test-task", time.Second, func() {})

	return taskMgr1, taskMgr2
}
