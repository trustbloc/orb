/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/sirupsen/logrus"
	"github.com/trustbloc/vct/pkg/client/vct"
)

var logger = logrus.New()

type vcStore interface {
	Get(id string) (*verifiable.Credential, error)
}

const (
	storeName       = "monitoring"
	keyPrefix       = "queue"
	tagNotConfirmed = "not_confirmed"
)

// HTTPClient represents HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client for the monitoring.
type Client struct {
	store   storage.Store
	http    HTTPClient
	vcStore vcStore
	ticker  *time.Ticker
}

// Opt represents client option func.
type Opt func(*Client)

// WithHTTPClient allows providing HTTP client.
func WithHTTPClient(client HTTPClient) Opt {
	return func(o *Client) {
		o.http = client
	}
}

// New returns monitoring client.
func New(provider storage.Provider, vcStore vcStore, opts ...Opt) (*Client, error) {
	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	client := &Client{
		store:   store,
		vcStore: vcStore,
		ticker:  time.NewTicker(time.Second),
		http:    &http.Client{Timeout: time.Minute},
	}

	for _, opt := range opts {
		opt(client)
	}

	go client.worker()

	return client, nil
}

// Proof represents response.
type Proof struct {
	Data struct {
		Domain  string    `json:"domain"`
		Created time.Time `json:"created"`
	} `json:"proof"`
}

type entity struct {
	CredentialID   string    `json:"credential_id"`
	ExpirationDate time.Time `json:"expiration_date"`
	Domain         string    `json:"domain"`
	Created        time.Time `json:"created"`
}

var errExpired = errors.New("expired")

func (c *Client) exist(e *entity) error {
	// validates whether the promise is valid against the end time
	if time.Now().UnixNano() > e.ExpirationDate.UnixNano() {
		return errExpired
	}

	// creates new client based on domain
	vctClient := vct.New(e.Domain, vct.WithHTTPClient(c.http))

	// gets initial credential from the store
	// *initial - a credential that was sent to VCT.
	vc, err := c.vcStore.Get(e.CredentialID)
	if err != nil {
		return fmt.Errorf("get credential %q: %w", e.CredentialID, err)
	}

	// calculates leaf hash for given timestamp and initial credential to be able query proof by hash.
	hash, err := vct.CalculateLeafHash(uint64(e.Created.UnixNano()/int64(time.Millisecond)), vc)
	if err != nil {
		return fmt.Errorf("calculate leaf hash: %w", err)
	}

	// gets latest signed tree head to get the latest tree size.
	sth, err := vctClient.GetSTH(context.Background())
	if err != nil {
		return fmt.Errorf("get STH: %w", err)
	}

	// gets proof by hash
	resp, err := vctClient.GetProofByHash(context.Background(), hash, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("get proof by hash: %w", err)
	}

	// checks that audit path it not zero
	if len(resp.AuditPath) < 1 {
		return errors.New("audit path cannot be zero")
	}

	return nil
}

func (c *Client) worker() {
	for range c.ticker.C {
		if err := c.handleEntities(); err != nil {
			logger.Errorf("handle entities: %v", err)
		}
	}
}

// Close stops ticker.
func (c *Client) Close() {
	c.ticker.Stop()
}

// Next is helper function that simplifies the usage of the iterator.
func Next(records interface{ Next() (bool, error) }) bool {
	ok, err := records.Next()
	if err != nil {
		logger.Errorf("next entity: %v", err)

		return false
	}

	return ok
}

func (c *Client) handleEntities() error {
	records, err := c.store.Query(tagNotConfirmed)
	if err != nil {
		return fmt.Errorf("query %q entities: %w", tagNotConfirmed, err)
	}

	defer records.Close() // nolint: errcheck

	for Next(records) {
		var src []byte

		if src, err = records.Value(); err != nil {
			return fmt.Errorf("get entity value: %w", err)
		}

		var e *entity
		if err = json.Unmarshal(src, &e); err != nil {
			logger.Errorf("unmarshal entity: %v", err)

			continue
		}

		err = c.exist(e)
		if err == nil {
			logger.Infof("credential %q existence in the Merkle tree confirmed", e.CredentialID)

			// removes the entity from the store bc we confirmed that credential is in MT (log above).
			if err = c.store.Delete(key(e.CredentialID)); err != nil {
				logger.Errorf("delete credential %q from queue: %v", e.CredentialID, err)
			}

			continue
		}

		if !errors.Is(err, errExpired) {
			logger.Warnf("credential %q existence: %v", e.CredentialID, err)

			continue
		}

		logger.Errorf("credential %q existence in the Merkle tree not confirmed", e.CredentialID)

		// removes entity from the store bc we failed our promise (log above).
		if err = c.store.Delete(key(e.CredentialID)); err != nil {
			logger.Errorf("delete credential %q from queue: %v", e.CredentialID, err)
		}
	}

	return nil
}

// Watch starts monitoring.
func (c *Client) Watch(anchorCredID string, endTime time.Time, proof []byte) error {
	var p *Proof

	if err := json.Unmarshal(proof, &p); err != nil {
		return fmt.Errorf("unmarshal proof: %w", err)
	}

	e := &entity{
		CredentialID:   anchorCredID,
		ExpirationDate: endTime,
		// TODO: domain probably needs to be discovered by using a web finger.
		Domain:  p.Data.Domain,
		Created: p.Data.Created,
	}

	err := c.exist(e)
	// no error means that we have credential in MT, no need to put it in the queue.
	if err == nil {
		logger.Infof("credential %q existence in the Merkle tree confirmed", e.CredentialID)

		return nil
	}

	// if error is ErrDataNotFound no need to put data in the queue.
	// No credential no work.
	if errors.Is(err, storage.ErrDataNotFound) {
		logger.Errorf("credential %q existence in the Merkle tree not confirmed", e.CredentialID)

		return err
	}

	// if error is errExpired no need to put data in the queue.
	if errors.Is(err, errExpired) {
		logger.Errorf("credential %q existence in the Merkle tree not confirmed", e.CredentialID)

		return err
	}

	logger.Warnf("credential %q existence: %v", e.CredentialID, err)
	logger.Warnf("credential %q is not in the Merkle tree yet, entity will escape to the queue", e.CredentialID)

	src, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal entity: %w", err)
	}

	// puts data in the queue, the entity will be picked and checked by the worker later.
	return c.store.Put(key(e.CredentialID), src, storage.Tag{Name: tagNotConfirmed}) // nolint: wrapcheck
}

func key(id string) string {
	return keyPrefix + id
}
