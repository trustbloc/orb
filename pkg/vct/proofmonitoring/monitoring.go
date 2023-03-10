/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package proofmonitoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/vct/pkg/client/vct"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/store"
	"github.com/trustbloc/orb/pkg/webfinger/model"
)

var logger = log.New("vct_monitor")

const (
	taskID            = "proof-monitor"
	storeName         = "proof-monitor"
	keyPrefix         = "queue"
	tagStatus         = "status"
	statusUnconfirmed = "unconfirmed"

	vctReadTokenKey  = "vct-read"
	vctWriteTokenKey = "vct-write"

	vctV1LedgerType = "vct-v1"
)

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type webfingerClient interface {
	GetLedgerType(domain string) (string, error)
}

// Client for the monitoring.
type Client struct {
	documentLoader ld.DocumentLoader
	store          storage.Store
	http           httpClient
	wfClient       webfingerClient
	requestTokens  map[string]string
}

type taskManager interface {
	RegisterTask(taskType string, interval time.Duration, task func())
}

// New returns monitoring client.
func New(provider storage.Provider, documentLoader ld.DocumentLoader, wfClient webfingerClient,
	httpClient httpClient, taskMgr taskManager, interval time.Duration,
	requestTokens map[string]string) (*Client, error) {
	s, err := store.Open(provider, storeName,
		store.NewTagGroup(tagStatus),
	)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	client := &Client{
		documentLoader: documentLoader,
		store:          s,
		http:           httpClient,
		wfClient:       wfClient,
		requestTokens:  requestTokens,
	}

	logger.Info("Registering task with Task Manager", logfields.WithTaskID(taskID), logfields.WithTaskMonitorInterval(interval))

	taskMgr.RegisterTask(taskID, interval, client.worker)

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
	CredentialRaw  []byte    `json:"credential"`
	ExpirationTime time.Time `json:"expirationTime"`
	Domain         string    `json:"domain"`
	Created        time.Time `json:"created"`
	Status         string    `json:"status"`
}

var errExpired = errors.New("expired")

func (c *Client) exist(e *entity) error {
	// validates whether the promise is valid against the end time
	if time.Now().UnixNano() > e.ExpirationTime.UnixNano() {
		return errExpired
	}

	// creates new client based on domain
	vctClient := vct.New(e.Domain, vct.WithHTTPClient(c.http), vct.WithAuthReadToken(c.requestTokens[vctReadTokenKey]),
		vct.WithAuthWriteToken(c.requestTokens[vctWriteTokenKey]))

	// calculates leaf hash for given timestamp and initial credential to be able to query proof by hash.
	hash, err := vct.CalculateLeafHash(uint64(e.Created.UnixNano()/int64(time.Millisecond)),
		e.CredentialRaw, c.documentLoader)
	if err != nil {
		return fmt.Errorf("calculate leaf hash: %w", err)
	}

	// gets latest signed tree head to get the latest tree size.
	sth, err := vctClient.GetSTH(context.Background())
	if err != nil {
		return fmt.Errorf("get STH from %s: %w", e.Domain, err)
	}

	if sth.TreeSize == 0 {
		return fmt.Errorf("tree size is zero for %s", e.Domain)
	}

	resp, err := vctClient.GetProofByHash(context.Background(), hash, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("get proof by hash from %s: %w", e.Domain, err)
	}

	// An audit path must exist if there is more than one log entry.
	if resp.LeafIndex > 0 && len(resp.AuditPath) == 0 {
		return fmt.Errorf("no audit path in proof from %s for leaf index %d", e.Domain, resp.LeafIndex)
	}

	return nil
}

func (c *Client) worker() {
	if err := c.handleEntities(); err != nil {
		logger.Error("Error handling entities", log.WithError(err))
	}
}

// Next is helper function that simplifies the usage of the iterator.
func Next(records interface{ Next() (bool, error) }) bool {
	ok, err := records.Next()
	if err != nil {
		logger.Error("Error getting next entity", log.WithError(err))

		return false
	}

	return ok
}

func (c *Client) handleEntities() error { //nolint:cyclop
	expr := fmt.Sprintf("%s:%s", tagStatus, statusUnconfirmed)

	records, err := c.store.Query(expr)
	if err != nil {
		return fmt.Errorf("query %s: %w", expr, err)
	}

	defer func() {
		if e := records.Close(); e != nil {
			log.CloseIteratorError(logger, e)
		}
	}()

	for Next(records) {
		var src []byte

		if src, err = records.Value(); err != nil {
			return fmt.Errorf("get entity value: %w", err)
		}

		var e *entity
		if err = json.Unmarshal(src, &e); err != nil {
			logger.Error("Error unmarshalling entity", log.WithError(err))

			continue
		}

		vc, err := verifiable.ParseCredential(e.CredentialRaw,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(c.documentLoader),
		)
		if err != nil {
			logger.Error("Error parsing credential", log.WithError(err))

			continue
		}

		err = c.exist(e)
		if err == nil {
			logger.Info("Credential existence in the ledger is confirmed",
				logfields.WithVerifiableCredentialID(vc.ID), logfields.WithDomain(e.Domain))

			// removes the entity from the store bc we confirmed that credential is in MT (log above).
			if err = c.store.Delete(key(vc.ID)); err != nil {
				logger.Error("Error deleting credential from queue",
					logfields.WithVerifiableCredentialID(vc.ID), log.WithError(err))
			}

			continue
		}

		if !errors.Is(err, errExpired) {
			logger.Warn("Error determining credential existence",
				logfields.WithVerifiableCredentialID(vc.ID), log.WithError(err))

			continue
		}

		logger.Error("Credential existence in the ledger not confirmed.",
			logfields.WithVerifiableCredentialID(vc.ID), logfields.WithDomain(e.Domain))

		// removes entity from the store bc we failed our promise (log above).
		if err = c.store.Delete(key(vc.ID)); err != nil {
			logger.Error("Error deleting credential from queue",
				logfields.WithVerifiableCredentialID(vc.ID), log.WithError(err))
		}
	}

	return nil
}

// Watch starts monitoring.
func (c *Client) Watch(vc *verifiable.Credential, endTime time.Time, domain string, created time.Time) error {
	if domain == "" {
		logger.Info("No domain for VC. Proof will not be monitored.", logfields.WithVerifiableCredentialID(vc.ID))

		return nil
	}

	lt, err := c.wfClient.GetLedgerType(domain)
	if err != nil {
		if errors.Is(err, model.ErrResourceNotFound) {
			logger.Info("Ledger not found for domain. Proof will not be monitored for VC.",
				logfields.WithDomain(domain), logfields.WithVerifiableCredentialID(vc.ID), log.WithError(err))

			return nil
		}

		return fmt.Errorf("get ledger type: %w", err)
	}

	if !isLedgerTypeSupported(lt) {
		logger.Warn("Ledger type for domain not supported. Proof will not be monitored for VC.",
			logfields.WithType(lt), logfields.WithDomain(domain), logfields.WithVerifiableCredentialID(vc.ID))

		return nil
	}

	return c.checkExistenceInLedger(vc, domain, created, endTime)
}

func (c *Client) checkExistenceInLedger(vc *verifiable.Credential, domain string, created, endTime time.Time) error {
	raw, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	e := &entity{
		ExpirationTime: endTime,
		Domain:         domain,
		Created:        created,
		Status:         statusUnconfirmed,
		CredentialRaw:  raw,
	}

	err = c.exist(e)
	// no error means that we have credential in MT, no need to put it in the queue.
	if err == nil {
		logger.Info("Credential existence in the ledger confirmed", logfields.WithVerifiableCredentialID(vc.ID),
			logfields.WithDomain(e.Domain))

		return nil
	}

	// if error is errExpired no need to put data in the queue.
	if errors.Is(err, errExpired) {
		logger.Error("Credential existence in the ledger not confirmed.", logfields.WithVerifiableCredentialID(vc.ID),
			logfields.WithDomain(e.Domain))

		return err
	}

	logger.Warn("Credential is not in the ledger yet. Will check again later.", logfields.WithVerifiableCredentialID(vc.ID),
		logfields.WithDomain(e.Domain), log.WithError(err))

	src, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal entity: %w", err)
	}

	// puts data in the queue, the entity will be picked and checked by the worker later.
	return c.store.Put(key(vc.ID), src,
		storage.Tag{Name: tagStatus, Value: statusUnconfirmed},
	)
}

func key(id string) string {
	return keyPrefix + id
}

func isLedgerTypeSupported(lt string) bool {
	return lt == vctV1LedgerType
}
