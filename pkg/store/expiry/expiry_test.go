/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package expiry

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
	"github.com/trustbloc/orb/pkg/taskmgr"
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
		// This is a timing-based test.
		// Here's the timeline:
		// t=0s   --->  test data stored, expiry services started
		// t=4s   --->  data 1 is now expired, will get deleted on next check by service1 (within 1s)
		// t=6s   --->  check to make sure data 1 was deleted
		// t=8s   --->  data 2 is now expired, will get deleted on next check by service1 (within 1s)
		// t=10s  --->  check to make sure data 2 was deleted and then stop service1, simulating server going down
		// t=12s  --->  data 3 is now expired, will get deleted on next check by service2 (within 4s - it has to detect
		//              that service1 is down first and then take over)
		// t=18s  --->  check to make sure data 3 was deleted and that service2's logs confirm that it took over from
		//              service1
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		storeToRunExpiryChecksOnName := "TestStore"

		storeToRunExpiryChecksOn, err := mongoDBProvider.OpenStore(storeToRunExpiryChecksOnName)
		require.NoError(t, err)

		expiryTagName := "ExpiryTime"

		err = mongoDBProvider.SetStoreConfig(storeToRunExpiryChecksOnName,
			storage.StoreConfiguration{TagNames: []string{expiryTagName}})
		require.NoError(t, err)

		testLogger := log.New("expiry-service-test")

		storeTestData(t, testLogger, expiryTagName, storeToRunExpiryChecksOn)

		coordinationStore, err := mongoDBProvider.OpenStore("orb-config")
		require.NoError(t, err)

		serviceInfo1, serviceInfo2, service2Logger := getTestExpiryServices(coordinationStore, storeToRunExpiryChecksOn,
			expiryTagName, storeToRunExpiryChecksOnName)

		serviceInfo1.taskMgr.Start()
		defer serviceInfo1.taskMgr.Stop()

		// Wait half a second so that we can ensure that service1 gets the permit and assigns itself the responsibility
		// of doing the expired data cleanup tasks. At the end of the test, we will be stopping service1 and checking to
		// see that service2 is able to take over.
		time.Sleep(time.Millisecond * 500)

		serviceInfo2.taskMgr.Start()
		defer serviceInfo2.taskMgr.Stop()

		runTimedChecks(t, testLogger, storeToRunExpiryChecksOn, serviceInfo1.taskMgr, service2Logger)
	})

	t.Run("Expiry handler error", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		storeToRunExpiryChecksOnName := "TestStore"

		storeToRunExpiryChecksOn, err := mongoDBProvider.OpenStore(storeToRunExpiryChecksOnName)
		require.NoError(t, err)

		expiryTagName := "ExpiryTime"

		err = mongoDBProvider.SetStoreConfig(storeToRunExpiryChecksOnName,
			storage.StoreConfiguration{TagNames: []string{expiryTagName}})
		require.NoError(t, err)

		testLogger := log.New("expiry-service-test")

		storeTestData(t, testLogger, expiryTagName, storeToRunExpiryChecksOn)

		coordinationStore, err := mongoDBProvider.OpenStore("orb-config")
		require.NoError(t, err)

		serviceInfo1, _, _ := getTestExpiryServices(coordinationStore, storeToRunExpiryChecksOn,
			expiryTagName, storeToRunExpiryChecksOnName,
			WithExpiryHandler(&mockExpiryHandler{Err: fmt.Errorf("expiry handler error")}))

		service1Logger := &stringLogger{}
		serviceInfo1.service.logger = service1Logger

		serviceInfo1.taskMgr.Start()
		defer serviceInfo1.taskMgr.Stop()

		// let service run couple of seconds in order to generate error message
		time.Sleep(5 * time.Second)

		ensureLogContainsMessage(t, service1Logger, "failed to invoke expiry handler: expiry handler error")
	})

	t.Run("Fail to query", func(t *testing.T) {
		store := &mock.Store{
			ErrQuery: errors.New("query error"),
		}

		coordinationStore, err := mem.NewProvider().OpenStore("orb-config")
		require.NoError(t, err)

		taskMgr := taskmgr.New(coordinationStore, time.Millisecond)

		service := NewService(taskMgr, time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		taskMgr.Start()
		defer taskMgr.Stop()

		ensureLogContainsMessage(t, logger, "failed to query store for expired data: query error")
	})
	t.Run("Fail to get next value from iterator", func(t *testing.T) {
		store := &mock.Store{
			QueryReturn: &mock.Iterator{ErrNext: errors.New("next error")},
		}

		coordinationStore, err := mem.NewProvider().OpenStore("orb-config")
		require.NoError(t, err)

		taskMgr := taskmgr.New(coordinationStore, time.Millisecond)

		service := NewService(taskMgr, time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		taskMgr.Start()
		defer taskMgr.Stop()

		ensureLogContainsMessage(t, logger, "failed to get next value from iterator: next error")
	})
	t.Run("Fail to get key from iterator", func(t *testing.T) {
		store := &mock.Store{
			QueryReturn: &mock.Iterator{NextReturn: true, ErrKey: errors.New("key error")},
		}

		coordinationStore, err := mem.NewProvider().OpenStore("orb-config")
		require.NoError(t, err)

		taskMgr := taskmgr.New(coordinationStore, time.Millisecond)

		service := NewService(taskMgr, time.Millisecond)
		service.Register(store, "ExpiryTag", "TestStore")

		logger := &stringLogger{}

		service.logger = logger

		taskMgr.Start()
		defer taskMgr.Stop()

		ensureLogContainsMessage(t, logger, "failed to get key from iterator: key error")
	})
}

func storeTestData(t *testing.T, testLogger *log.Log, expiryTagName string, store storage.Store) {
	t.Helper()

	data1ExpiryTime := time.Now().Add(time.Second * 4).Unix()  // Will get deleted by service1
	data2ExpiryTime := time.Now().Add(time.Second * 8).Unix()  // Will get deleted by service1
	data3ExpiryTime := time.Now().Add(time.Second * 12).Unix() // Will get deleted by service2
	data4ExpiryTime := time.Now().Add(time.Minute).Unix()      // Far in the future - won't be expired during this test.

	testLogger.Infof("Data 1 will expire at %s, data 2 will expire at %s, "+
		"data 3 will expire at %s, and data 4 will expire at %s.", time.Unix(data1ExpiryTime, 0).String(),
		time.Unix(data2ExpiryTime, 0).String(), time.Unix(data3ExpiryTime, 0).String(),
		time.Unix(data4ExpiryTime, 0).String())

	operations := []storage.Operation{
		{
			Key:   "Key1",
			Value: []byte("TestValue1"),
			Tags: []storage.Tag{
				{
					Name:  expiryTagName,
					Value: fmt.Sprintf("%d", data1ExpiryTime),
				},
			},
		},
		{
			Key:   "Key2",
			Value: []byte("TestValue2"),
			Tags: []storage.Tag{
				{
					Name:  expiryTagName,
					Value: fmt.Sprintf("%d", data2ExpiryTime),
				},
			},
		},
		{
			Key:   "Key3",
			Value: []byte("TestValue3"),
			Tags: []storage.Tag{
				{
					Name:  expiryTagName,
					Value: fmt.Sprintf("%d", data3ExpiryTime),
				},
			},
		},
		{
			Key:   "Key4",
			Value: []byte("TestValue4"),
			Tags: []storage.Tag{
				{
					Name:  expiryTagName,
					Value: fmt.Sprintf("%d", data4ExpiryTime),
				},
			},
		},
	}
	err := store.Batch(operations)
	require.NoError(t, err)

	testLogger.Infof("Successfully stored test data.")
}

type serviceInfo struct {
	service *Service
	taskMgr *taskmgr.Manager
}

// We return the started services so that the caller can call service.Stop on them when the test is done.
// service2's logger is returned, so it can be examined later on in the test.
func getTestExpiryServices(coordinationStore storage.Store, storeToRunExpiryChecksOn storage.Store,
	expiryTagName, storeName string, opts ...Option) (*serviceInfo, *serviceInfo, *stringLogger) {
	taskMgr1 := taskmgr.New(coordinationStore, time.Second)

	service1 := NewService(taskMgr1, time.Second)

	service1LoggerModule := "expiry-service1"
	service1Logger := log.New(service1LoggerModule)

	service1.logger = service1Logger

	log.SetLevel(service1LoggerModule, log.DEBUG)

	service1.Register(storeToRunExpiryChecksOn, expiryTagName, storeName, opts...)

	taskMgr2 := taskmgr.New(coordinationStore, time.Second)

	service2 := NewService(taskMgr2, time.Second)

	service2LoggerModule := "expiry-service2"

	service2Logger := &stringLogger{
		passthroughLogger: log.New(service2LoggerModule),
	}

	service2.logger = service2Logger

	log.SetLevel(service2LoggerModule, log.DEBUG)

	service2.Register(storeToRunExpiryChecksOn, expiryTagName, storeName, opts...)

	return &serviceInfo{
			service: service1,
			taskMgr: taskMgr1,
		},
		&serviceInfo{
			service: service2,
			taskMgr: taskMgr2,
		},
		service2Logger
}

func runTimedChecks(t *testing.T, testLogger *log.Log,
	storeToRunExpiryChecksOn storage.Store, taskMgr *taskmgr.Manager, service2Logger *stringLogger) {
	t.Helper()

	waitTime := time.Second * 6

	testLogger.Infof("Waiting %s.", waitTime.String())

	time.Sleep(waitTime)

	testLogger.Infof("Finished waiting %s seconds. Checking to see if Key1 was "+
		"deleted as expected (while Key2, Key3, and Key4 remain since they haven't expired yet).", waitTime.String())

	doFirstSetOfChecks(t, testLogger, storeToRunExpiryChecksOn)

	testLogger.Infof("Waiting %s.", waitTime.String())

	waitTime = time.Second * 4

	time.Sleep(waitTime)

	testLogger.Infof("Finished waiting %s. Checking to see if Key2 "+
		"was deleted as expected (while Key3 and Key4 remain since they haven't expired yet).", waitTime.String())

	doSecondSetOfChecks(t, testLogger, storeToRunExpiryChecksOn)

	// Simulate what happens if an Orb instance goes down.
	// service1 should currently be holding the permit that gives it the responsibility to do the expired data cleanup.
	testLogger.Infof("Stopping service1, simulating a server failure. service2 should take over before the " +
		"next check and be the one who deletes Key3.")

	taskMgr.Stop()

	waitTime = time.Second * 6

	testLogger.Infof("Waiting %s.", waitTime.String())

	time.Sleep(waitTime)

	testLogger.Infof("Finished waiting %s. Checking service2's logs to make sure it took over.",
		waitTime.String())

	doFinalSetOfChecks(t, testLogger, storeToRunExpiryChecksOn, service2Logger)
}

func doFirstSetOfChecks(t *testing.T, testLogger *log.Log, storeToRunExpiryChecksOn storage.Store) {
	t.Helper()

	_, err := storeToRunExpiryChecksOn.Get("Key1")
	require.Equal(t, storage.ErrDataNotFound, err, "Expected Key1 to be deleted.")

	testLogger.Infof("Key1 was deleted as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key2")
	require.NoError(t, err, "Expected Key2 to be found.")

	testLogger.Infof("Key2 still remains as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key3")
	require.NoError(t, err, "Expected Key3 to be found.")

	testLogger.Infof("Key3 still remains as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key4")
	require.NoError(t, err, "Expected Key4 to be found.")

	testLogger.Infof("Key4 still remains as expected.")
}

func doSecondSetOfChecks(t *testing.T, testLogger *log.Log, storeToRunExpiryChecksOn storage.Store) {
	t.Helper()

	_, err := storeToRunExpiryChecksOn.Get("Key2")
	require.Equal(t, storage.ErrDataNotFound, err, "Expected Key2 to be deleted.")

	testLogger.Infof("Key2 was deleted as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key3")
	require.NoError(t, err, "Expected Key3 to be found.")

	testLogger.Infof("Key3 still remains as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key4")
	require.NoError(t, err, "Expected Key4 to be found.")

	testLogger.Infof("Key4 still remains as expected.")
}

func doFinalSetOfChecks(t *testing.T, testLogger *log.Log, storeToRunExpiryChecksOn storage.Store,
	service2Logger *stringLogger) {
	t.Helper()

	require.Contains(t, service2Logger.Read(), "Successfully deleted 1 pieces of expired data.")

	testLogger.Infof("service2's logs confirm that it took over and deleted a piece of data (should be Key3).")

	testLogger.Infof("Checking to see if Key3 was deleted as expected (while Key4 remains since it " +
		"hasn't expired yet).")

	_, err := storeToRunExpiryChecksOn.Get("Key3")
	require.Equal(t, storage.ErrDataNotFound, err, "Expected Key3 to be deleted.")

	testLogger.Infof("Key3 was deleted as expected.")

	_, err = storeToRunExpiryChecksOn.Get("Key4")
	require.NoError(t, err, "Expected Key4 to be found.")

	testLogger.Infof("Key4 still remains as expected.")
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

type mockExpiryHandler struct {
	Err error
}

func (m *mockExpiryHandler) HandleExpiredKeys(_ ...string) error {
	return m.Err
}
