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
	"github.com/trustbloc/orb/pkg/lifecycle"
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

	defaultMonitoringInterval = 10 * time.Second
	defaultMaxRecordsPerRun   = 50
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
	*lifecycle.Lifecycle
	*options

	documentLoader ld.DocumentLoader
	store          storage.Store
	http           httpClient
	wfClient       webfingerClient
}

type taskManager interface {
	RegisterTaskEx(taskType string, interval time.Duration, task func() time.Duration)
}

type options struct {
	monitoringInterval    time.Duration
	requestTokens         map[string]string
	maxRecordsPerInterval int
}

// Opt specifies a proof monitoring option.
type Opt func(opts *options)

// WithMonitoringInterval sets the proof monitoring interval.
func WithMonitoringInterval(value time.Duration) Opt {
	return func(opts *options) {
		opts.monitoringInterval = value
	}
}

// WithRequestTokens sets the request bearer tokens for HTTP requests to the VCT service.
func WithRequestTokens(value map[string]string) Opt {
	return func(opts *options) {
		opts.requestTokens = value
	}
}

// WithMaxRecordsPerInterval sets the maximum number of records to check in a single monitoring interval.
func WithMaxRecordsPerInterval(value int) Opt {
	return func(opts *options) {
		opts.maxRecordsPerInterval = value
	}
}

// New returns monitoring client.
func New(provider storage.Provider, documentLoader ld.DocumentLoader, wfClient webfingerClient,
	httpClient httpClient, taskMgr taskManager, opts ...Opt,
) (*Client, error) {
	s, err := store.Open(provider, storeName,
		store.NewTagGroup(tagStatus),
	)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	options := resolveOptions(opts)

	client := &Client{
		Lifecycle:      lifecycle.New("proof-monitor"),
		options:        options,
		documentLoader: documentLoader,
		store:          s,
		http:           httpClient,
		wfClient:       wfClient,
	}

	client.Start()

	logger.Info("Registering task with Task Manager", logfields.WithTaskID(taskID),
		logfields.WithTaskMonitorInterval(options.monitoringInterval))

	taskMgr.RegisterTaskEx(taskID, options.monitoringInterval, client.worker)

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

func (c *Client) worker() time.Duration {
	nextInterval, err := c.handleEntities()
	if err != nil {
		logger.Error("Error handling entities", log.WithError(err))
	}

	return nextInterval
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

func (c *Client) handleEntities() (time.Duration, error) {
	expr := fmt.Sprintf("%s:%s", tagStatus, statusUnconfirmed)

	it, err := c.store.Query(expr)
	if err != nil {
		return 0, fmt.Errorf("query %s: %w", expr, err)
	}

	defer store.CloseIterator(it)

	numProcessed := 0

	for Next(it) {
		if c.Lifecycle.State() != lifecycle.StateStarted {
			logger.Info("Proof monitor service is not in state 'started'. Exiting.")

			return 0, nil
		}

		if numProcessed >= c.maxRecordsPerInterval {
			logger.Info("Reached the maximum number of proof monitor records per interval. Exiting.",
				logfields.WithRecordsProcessed(numProcessed))

			// Since we know we have more records, the next run time will be sooner.
			return c.monitoringInterval / 3, nil
		}

		var src []byte

		if src, err = it.Value(); err != nil {
			return 0, fmt.Errorf("get entity value: %w", err)
		}

		numProcessed++

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

	return 0, nil
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

func resolveOptions(opts []Opt) *options {
	options := &options{
		monitoringInterval:    defaultMonitoringInterval,
		maxRecordsPerInterval: defaultMaxRecordsPerRun,
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}
