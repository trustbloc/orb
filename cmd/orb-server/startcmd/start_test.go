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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	ariesmockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	ariesspi "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	awssvc "github.com/trustbloc/kms/pkg/aws"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

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
			kmsParams: &kmsParameters{
				kmsSecretsDatabaseType: databaseTypeCouchDBOption,
				kmsType:                kmsLocal,
			},
			dbParameters: &dbParameters{
				databaseType: databaseTypeMemOption,
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
			kmsParams: &kmsParameters{
				kmsSecretsDatabaseType: "data1",
				kmsType:                kmsLocal,
			},
			dbParameters: &dbParameters{
				databaseType: databaseTypeMemOption,
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func TestCreateKMSAndCrypto(t *testing.T) {
	t.Run("Success (webkms)", func(t *testing.T) {
		km, cr, err := createKMSAndCrypto(&orbParameters{
			kmsParams: &kmsParameters{
				kmsEndpoint: "https://example.com/keystores",
				kmsType:     kmsWeb,
			},
		}, nil, nil, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, km)
		require.NotNil(t, cr)
	})

	t.Run("Success (local kms)", func(t *testing.T) {
		cfgStore, err := mem.NewProvider().OpenStore("cfg")
		require.NoError(t, err)

		km, cr, err := createKMSAndCrypto(&orbParameters{
			kmsParams: &kmsParameters{
				kmsSecretsDatabaseType: "mem",
				kmsType:                kmsLocal,
			},
		}, nil, mem.NewProvider(), cfgStore, nil)
		require.NoError(t, err)
		require.NotNil(t, km)
		require.NotNil(t, cr)
	})

	t.Run("Fail to create Aries KMS store wrapper", func(t *testing.T) {
		masterKeyStore, err := mem.NewProvider().OpenStore("masterkeystore")
		require.NoError(t, err)

		km, cr, err := createKMSAndCrypto(&orbParameters{
			kmsParams: &kmsParameters{
				kmsSecretsDatabaseType: "mem",
				kmsType:                kmsLocal,
			},
		}, nil, &ariesmockstorage.Provider{
			ErrOpenStore: errors.New("test error"),
		}, masterKeyStore, nil)
		require.EqualError(t, err, "create Aries KMS store wrapper: test error")
		require.Nil(t, km)
		require.Nil(t, cr)
	})
}

func TestCreateLocalKMS(t *testing.T) {
	t.Run("Fail to create kms", func(t *testing.T) {
		km, cr, err := createLocalKMS("", "", mem.NewProvider())
		require.EqualError(t, err, "create kms: new: failed to create new keywrapper: "+
			"keyURI must have a prefix in form 'prefixname://'")
		require.Nil(t, km)
		require.Nil(t, cr)
	})
}

type mockMetricsProvider struct {
}

func (m *mockMetricsProvider) SignCount() {
}

func (m *mockMetricsProvider) SignTime(time.Duration) {
}

func (m *mockMetricsProvider) ExportPublicKeyCount() {
}

func (m *mockMetricsProvider) ExportPublicKeyTime(time.Duration) {
}

func (m *mockMetricsProvider) VerifyCount() {
}

func (m *mockMetricsProvider) VerifyTime(time.Duration) {
}

func TestAWSKMSWrapper(t *testing.T) {
	endpoint := "http://localhost"
	awsSession, err := session.NewSession(&aws.Config{
		Endpoint:                      &endpoint,
		Region:                        aws.String("ca"),
		CredentialsChainVerboseErrors: aws.Bool(true),
	})
	awsService := awssvc.New(awsSession, &mockMetricsProvider{}, "")

	wrapper := awsKMSWrapper{service: awsService}

	keyID, handle, err := wrapper.Create("")
	require.EqualError(t, err, "key not supported ")
	require.Empty(t, "", keyID)
	require.Nil(t, handle)

	handle, err = wrapper.Get("")
	require.NoError(t, err)
	require.Equal(t, "", handle)

	keyID, handle, err = wrapper.ImportPrivateKey(nil, "")
	require.EqualError(t, err, "not implemented")
	require.Empty(t, keyID)
	require.Nil(t, handle)
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
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHttpUrlFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + vcSignPrivateKeysFlagName, "k1=value",
			"--" + vcSignActiveKeyIDFlagName, "k2",
			"--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, "local",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "vc sign active key id k2 not exist in vc private keys")
	})

	t.Run("http sign active key not exist in http private key", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHttpUrlFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + httpSignPrivateKeyFlagName, "k1=value",
			"--" + httpSignActiveKeyIDFlagName, "k2",
			"--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, "local",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "http sign active key id k2 not exist in http private key")
	})

	t.Run("http private key include more than one key", func(t *testing.T) {
		startCmd := GetStartCmd()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080",
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHttpUrlFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + httpSignPrivateKeyFlagName, "k1=value",
			"--" + httpSignPrivateKeyFlagName, "k2=value2",
			"--" + httpSignActiveKeyIDFlagName, "k2",
			"--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, "local",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "http sign private key include more than one key")
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
			"--" + metricsProviderFlagName, "prometheus",
			"--" + promHttpUrlFlagName, "localhost:8081",
			"--" + casTypeFlagName, "local",
			"--" + didNamespaceFlagName, "namespace",
			"--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption,
			"--" + anchorCredentialDomainFlagName, "domain.com",
			"--" + secretLockKeyPathFlagName, "./key.file",
			"--" + vcSignActiveKeyIDFlagName, "k1",
			"--" + kmsTypeFlagName, "local",
			"--" + kmsSecretsDatabaseTypeFlagName, "mem",
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

func (m *mockActivityLogger) Debug(msg string, fields ...zap.Field) {
	m.mutex.Lock()

	w := msg

	for _, f := range fields {
		var value string

		switch f.Type {
		case zapcore.StringType:
			value = f.String
		case zapcore.StringerType:
			value = fmt.Sprintf("%s", f.Interface)
		}

		w += fmt.Sprintf(" %s=%s", f.Key, value)
	}

	m.infos = append(m.infos, w)

	m.mutex.Unlock()
}

func (m *mockActivityLogger) Warn(msg string, fields ...zap.Field) {
	m.mutex.Lock()

	w := msg

	for _, f := range fields {
		var value string

		switch f.Type {
		case zapcore.StringType:
			value = f.String
		case zapcore.StringerType:
			value = fmt.Sprintf("%s", f.Interface)
		}

		w += fmt.Sprintf(" %s=%s", f.Key, value)
	}

	m.warns = append(m.infos, w)

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
		"Received activity activityId=https://domain1.com/123 activityType=Reject actorId=https://domain2.com/456")
	require.Contains(t, l.getInfos(),
		"Received activity activityId=https://domain2.com/456 activityType=Accept actorId=https://domain1.com/123")
}
