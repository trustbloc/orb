/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestCreateProviders(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startOrbServices(&orbParameters{dbParameters: &dbParameters{databaseType: databaseTypeCouchDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})
	t.Run("test error from create new mysql", func(t *testing.T) {
		err := startOrbServices(&orbParameters{dbParameters: &dbParameters{databaseType: databaseTypeMYSQLDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB URL for new mySQL DB provider can't be blank")
	})
	t.Run("test error from create new kms secrets couchdb", func(t *testing.T) {
		err := startOrbServices(&orbParameters{
			dbParameters: &dbParameters{databaseType: databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeCouchDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})
	t.Run("test error from create new kms secrets mysql", func(t *testing.T) {
		err := startOrbServices(&orbParameters{
			dbParameters: &dbParameters{databaseType: databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeMYSQLDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB URL for new mySQL DB provider can't be blank")
	})
	t.Run("test invalid database type", func(t *testing.T) {
		err := startOrbServices(&orbParameters{dbParameters: &dbParameters{databaseType: "data1"}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
	t.Run("test invalid kms secrets database type", func(t *testing.T) {
		err := startOrbServices(&orbParameters{
			dbParameters: &dbParameters{databaseType: databaseTypeMemOption,
				kmsSecretsDatabaseType: "data1"}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func TestCreateKMS(t *testing.T) {
	t.Run("fail to open master key store", func(t *testing.T) {
		localKMS, err := createKMS(&ariesmockstorage.MockStoreProvider{FailNamespace: "masterkey"})

		require.Nil(t, localKMS)
		require.EqualError(t, err, "failed to open store for name space masterkey")
	})
	t.Run("fail to create master key service", func(t *testing.T) {
		masterKeyStore := ariesmockstorage.MockStore{
			Store:     make(map[string][]byte),
			ErrPut:    nil,
			ErrGet:    nil,
			ErrItr:    nil,
			ErrDelete: nil,
		}

		err := masterKeyStore.Put("masterkey", []byte(""))
		require.NoError(t, err)

		localKMS, err := createKMS(&ariesmockstorage.MockStoreProvider{Store: &masterKeyStore})
		require.EqualError(t, err, "masterKeyReader is empty")
		require.Nil(t, localKMS)
	})
}

func TestPrepareMasterKeyReader(t *testing.T) {
	t.Run("Unexpected error when trying to retrieve master key from store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: errors.New("testError")}})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
	t.Run("Error when putting newly generated master key into store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: storage.ErrDataNotFound,
					ErrPut: errors.New("testError")}})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
}



