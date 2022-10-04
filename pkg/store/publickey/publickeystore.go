/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package publickey

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bluele/gcache"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/store"
)

var logger = log.NewStructured("public-key-store")

const (
	storeName    = "public-key"
	maxCacheSize = 1000
)

// Store manages a persistent store of public keys for issuers. The store also caches
// the public keys for better performance.
type Store struct {
	cache          gcache.Cache
	store          storage.Store
	fetchPublicKey verifiable.PublicKeyFetcher
}

type cacheKey struct {
	issuerID string
	keyID    string
}

// New returns a new public key store.
func New(p storage.Provider, fetchPublicKey verifiable.PublicKeyFetcher) (*Store, error) {
	s, err := store.Open(p, storeName)
	if err != nil {
		return nil, fmt.Errorf("open store [%s]: %w", storeName, err)
	}

	pkStore := &Store{
		store:          s,
		fetchPublicKey: fetchPublicKey,
	}

	pkCache := gcache.New(maxCacheSize).ARC().
		LoaderFunc(
			func(k interface{}) (interface{}, error) {
				ck := k.(cacheKey) //nolint:errcheck,forcetypeassert

				return pkStore.get(ck.issuerID, ck.keyID)
			},
		).Build()

	pkStore.cache = pkCache

	logger.Info("Created public key store", log.WithStoreName(storeName))

	return pkStore, nil
}

// GetPublicKey returns the public key for the given issuer and key ID.
func (c *Store) GetPublicKey(issuerID, keyID string) (*verifier.PublicKey, error) {
	pk, err := c.cache.Get(cacheKey{issuerID, keyID})
	if err != nil {
		return nil, err
	}

	return pk.(*verifier.PublicKey), nil
}

func (c *Store) get(issuerID, keyID string) (*verifier.PublicKey, error) {
	logger.Info("Loading public key into cache for issuer",
		log.WithIssuer(issuerID), log.WithKeyID(keyID))

	pk, err := c.getFromDB(issuerID, keyID)
	if err == nil {
		return pk, nil
	}

	if !errors.Is(err, storage.ErrDataNotFound) {
		return nil, fmt.Errorf("get from DB: %w", err)
	}

	logger.Info("Public key not found in storage. Fetching public key from server for issuer.",
		log.WithIssuer(issuerID), log.WithKeyID(keyID))

	// Public key not found in storage. Retrieve it from the server.
	pk, err = c.fetchPublicKey(issuerID, keyID)
	if err != nil {
		return nil, fmt.Errorf("fetch public key from server - issuer [%s], key ID [%s]: %w",
			issuerID, keyID, err)
	}

	err = c.putToDB(issuerID, keyID, pk)
	if err != nil {
		// We couldn't store the public key but this shouldn't result in a client error. Just log a warning.
		logger.Warn("Error storing public key for issuer",
			log.WithIssuer(issuerID), log.WithKeyID(keyID), log.WithError(err))
	}

	return pk, nil
}

func (c *Store) getFromDB(issuerID, keyID string) (*verifier.PublicKey, error) {
	key := fmt.Sprintf("%s-%s", issuerID, keyID)

	pkBytes, err := c.store.Get(key)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, fmt.Errorf("get key - issuer [%s], key ID [%s]: %w", issuerID, keyID, err)
		}

		return nil, fmt.Errorf("database error getting public key for issuer [%s], key ID [%s]: %w",
			issuerID, keyID, err)
	}

	logger.Info("Public key found in storage for issuer", log.WithIssuer(issuerID), log.WithKeyID(keyID))

	pk := &verifier.PublicKey{}

	err = json.Unmarshal(pkBytes, pk)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public key - issuer [%s], key ID [%s]: %w",
			issuerID, keyID, err)
	}

	return pk, nil
}

func (c *Store) putToDB(issuerID, keyID string, pk *verifier.PublicKey) error {
	key := fmt.Sprintf("%s-%s", issuerID, keyID)

	pkBytes, err := json.Marshal(pk)
	if err != nil {
		return fmt.Errorf("marshal public key - issuer [%s], key ID [%s]: %w",
			issuerID, keyID, err)
	}

	logger.Info("Storing public key for issuer", log.WithIssuer(issuerID), log.WithKeyID(keyID))

	err = c.store.Put(key, pkBytes)
	if err != nil {
		return fmt.Errorf("store public key - issuer [%s], key ID [%s]: %w",
			issuerID, keyID, err)
	}

	return nil
}
