/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesspi "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

func TestCreateProviders(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startOrbServices(&orbParameters{dbParameters: &dbParameters{databaseType: databaseTypeCouchDBOption}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB: url can't be blank")
	})
	t.Run("test error from create new kms secrets couchdb", func(t *testing.T) {
		err := startOrbServices(&orbParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeCouchDBOption,
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB: url can't be blank")
	})
	t.Run("test invalid database type", func(t *testing.T) {
		err := startOrbServices(&orbParameters{dbParameters: &dbParameters{databaseType: "data1"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
	t.Run("test invalid kms secrets database type", func(t *testing.T) {
		err := startOrbServices(&orbParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: "data1",
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func TestCreateKMSAndCrypto(t *testing.T) {
	t.Run("Success (webkms)", func(t *testing.T) {
		km, cr, err := createKMSAndCrypto(&orbParameters{
			kmsStoreEndpoint: "https://example.com",
		}, nil, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, km)
		require.NotNil(t, cr)
	})

	t.Run("Success (local kms)", func(t *testing.T) {
		cfgStore, err := mem.NewProvider().OpenStore("cfg")
		require.NoError(t, err)

		km, cr, err := createKMSAndCrypto(&orbParameters{}, nil, mem.NewProvider(), cfgStore)
		require.NoError(t, err)
		require.NotNil(t, km)
		require.NotNil(t, cr)
	})

	t.Run("Fail to create kms", func(t *testing.T) {
		masterKeyStore, err := mem.NewProvider().OpenStore("masterkeystore")
		require.NoError(t, err)

		km, cr, err := createKMSAndCrypto(&orbParameters{}, nil, &ariesmockstorage.Provider{
			ErrOpenStore: errors.New("test error"),
		}, masterKeyStore)
		require.EqualError(t, err, "create kms: new: failed to ceate local kms: test error")
		require.Nil(t, km)
		require.Nil(t, cr)
	})
}

func TestGetOrInit(t *testing.T) {
	testErr := errors.New("error")

	require.True(t, errors.Is(getOrInit(
		&ariesmockstorage.Store{ErrGet: testErr}, "key", nil, func() (interface{}, error) {
			return "", nil
		}, 1,
	), testErr))

	require.True(t, errors.Is(getOrInit(
		&ariesmockstorage.Store{ErrGet: ariesspi.ErrDataNotFound, ErrPut: testErr}, "key", nil,
		func() (interface{}, error) {
			return nil, nil
		}, 1,
	), testErr))

	cfgStore, err := mem.NewProvider().OpenStore("cfg")
	require.NoError(t, err)

	require.Contains(t, getOrInit(
		cfgStore, "key", nil, func() (interface{}, error) {
			return map[string]interface{}{"test": make(chan int)}, nil
		}, 1,
	).Error(), "marshal config value for \"key\"")
}

func TestPrivateKeys(t *testing.T) {
	t.Run("active key not exist in private key", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + privateKeysFlagName, "k1=value",
			"--" + activeKeyIDFlagName, "k2",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "active key id k2 not exist in private keys")
	})

	t.Run("private keys not optional if active key exist", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + activeKeyIDFlagName, "k2",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "Neither private-keys (command line flag) nor ORB_PRIVATE_KEYS (environment variable) have been set")
	})
}

func TestPrepareMasterKeyReader(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		lock, err := prepareKeyLock("")
		require.NoError(t, err)
		require.NotNil(t, lock)
	})

	t.Run("Wrong path", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + hostMetricsURLFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + vctURLFlagName, "localhost:8081",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialSignatureSuiteFlagName, "suite",
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + anchorCredentialIssuerFlagName, "issuer.com",
			"--" + anchorCredentialURLFlagName, "peer.com",
			"--" + secretLockKeyPathFlagName, "./key.file",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "open key.file: no such file or directory")
	})
}

type mockActivityLogger struct {
	infos []string
	warns []string
	mutex sync.Mutex
}

func (m *mockActivityLogger) Infof(msg string, args ...interface{}) {
	m.mutex.Lock()
	m.infos = append(m.infos, fmt.Sprintf(msg, args...))
	m.mutex.Unlock()
}

func (m *mockActivityLogger) Warnf(msg string, args ...interface{}) {
	m.mutex.Lock()
	m.warns = append(m.warns, fmt.Sprintf(msg, args...))
	m.mutex.Unlock()
}

func (m *mockActivityLogger) getInfos() []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.infos
}

func (m *mockActivityLogger) getWarns() []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	return m.warns
}

func TestMonitorActivities(t *testing.T) {
	activityChan := make(chan *vocab.ActivityType)

	l := &mockActivityLogger{}

	go monitorActivities(activityChan, l)

	activityChan <- vocab.NewRejectActivity(vocab.NewObjectProperty(),
		vocab.WithID(vocab.MustParseURL("https://domain1.com/123")),
		vocab.WithActor(vocab.MustParseURL("https://domain2.com/456")),
	)

	activityChan <- vocab.NewAcceptActivity(vocab.NewObjectProperty(),
		vocab.WithID(vocab.MustParseURL("https://domain2.com/456")),
		vocab.WithActor(vocab.MustParseURL("https://domain1.com/123")),
	)

	time.Sleep(10 * time.Millisecond)

	close(activityChan)

	require.Contains(t, l.getWarns(),
		"Received activity [https://domain1.com/123] of type Reject from [https://domain2.com/456]")
	require.Contains(t, l.getInfos(),
		"Received activity [https://domain2.com/456] of type Accept from [https://domain1.com/123]")
}
