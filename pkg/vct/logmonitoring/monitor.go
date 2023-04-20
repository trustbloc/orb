/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitoring

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/canonicalizer"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
	"go.uber.org/zap"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	storeutil "github.com/trustbloc/orb/pkg/store"
	"github.com/trustbloc/orb/pkg/store/logentry"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
	"github.com/trustbloc/orb/pkg/vct/logmonitoring/verifier"
)

var logger = log.New("vct-consistency-monitor")

const (
	// VCT limits maximum number of entries to 1000.
	defaultMaxGetEntriesRange = 1000

	// maximum in-memory tree size.
	defaultMaxTreeSize = 10000

	vctReadTokenKey  = "vct-read"
	vctWriteTokenKey = "vct-write"

	defaultRecoveryFetchSize = 500
)

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type logMonitorStore interface {
	GetActiveLogs() ([]*logmonitor.LogMonitor, error)
	Update(log *logmonitor.LogMonitor) error
}

type logEntryStore interface {
	StoreLogEntries(log string, start, end uint64, entries []command.LeafEntry) error
	GetLogEntriesFrom(logURL string, start uint64) (logentry.EntryIterator, error)
	FailLogEntriesFrom(logURL string, start uint64) error
}

type logVerifier interface {
	VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error
	GetRootHashFromEntries(entries []*command.LeafEntry) ([]byte, error)
}

/*	Monitors watch logs and check that they behave correctly.
	In order to do this, it should follow these steps for each log:
		1.  Fetch the current STH.
		2.  Verify the STH signature.
		3.  Fetch all the entries in the tree corresponding to the STH.
		4.  Confirm that the tree made from the fetched entries produces the same hash as that in the STH.
   		5.  Fetch the current STH.  Repeat until the STH changes.
   		6.  Verify the STH signature.
   		7.  Fetch all the new entries in the tree corresponding to the STH.
   		8.  Either:
		   1.  Verify that the updated list of all entries generates a tree
			   with the same hash as the new STH.

       		Or, if it is not keeping all log entries:

			2.  Fetch a consistency proof for the new STH with the previous STH.
			3.  Verify the consistency proof.
			4.  Verify that the new entries generate the corresponding elements in the consistency proof.
*/

// Client implements periodical monitoring of VCT consistency
// as per https://datatracker.ietf.org/doc/html/rfc6962#section-5.3.
type Client struct {
	logVerifier          logVerifier
	monitorStore         logMonitorStore
	entryStore           logEntryStore
	entryStoreEnabled    bool
	http                 httpClient
	requestTokens        map[string]string
	maxTreeSize          uint64
	maxGetEntriesRange   int
	maxRecoveryFetchSize int
}

// Option is an option for resolve handler.
type Option func(opts *Client)

// WithMaxTreeSize sets optional maximum tree size for assembling tree in order to check new STH.
func WithMaxTreeSize(maxTreeSize uint64) Option {
	return func(opts *Client) {
		opts.maxTreeSize = maxTreeSize
	}
}

// WithMaxGetEntriesRange sets optional limit for number of entries retrieved.
func WithMaxGetEntriesRange(max int) Option {
	return func(opts *Client) {
		opts.maxGetEntriesRange = max
	}
}

// WithMaxRecoveryFetchSize sets an optional limit for number of entries retrieved during recover.
func WithMaxRecoveryFetchSize(max int) Option {
	return func(opts *Client) {
		opts.maxRecoveryFetchSize = max
	}
}

// WithLogEntriesStore sets optional implementation of log entries store (default is noop store).
func WithLogEntriesStore(s logEntryStore) Option {
	return func(opts *Client) {
		opts.entryStore = s
	}
}

// WithLogEntriesStoreEnabled enables log entries store (default is false).
func WithLogEntriesStoreEnabled(enabled bool) Option {
	return func(opts *Client) {
		opts.entryStoreEnabled = enabled
	}
}

// New returns new client for monitoring VCT log consistency.
func New(store logMonitorStore, httpClient httpClient, requestTokens map[string]string, opts ...Option) (*Client, error) {
	client := &Client{
		logVerifier:          verifier.New(),
		monitorStore:         store,
		entryStoreEnabled:    false,
		entryStore:           &noopLogEntryStore{},
		http:                 httpClient,
		requestTokens:        requestTokens,
		maxTreeSize:          defaultMaxTreeSize,
		maxGetEntriesRange:   defaultMaxGetEntriesRange,
		maxRecoveryFetchSize: defaultRecoveryFetchSize,
	}

	// apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func (c *Client) checkVCTConsistency(logMonitor *logmonitor.LogMonitor) error {
	logger.Debug("Checking VCT consistency...", logfields.WithLogURLString(logMonitor.Log))

	storedSTH := logMonitor.STH

	// creates new client based on log
	vctClient := vct.New(logMonitor.Log, vct.WithHTTPClient(c.http),
		vct.WithAuthWriteToken(c.requestTokens[vctWriteTokenKey]),
		vct.WithAuthReadToken(c.requestTokens[vctReadTokenKey]))

	// gets the latest signed tree head and compare to stored one
	sth, err := vctClient.GetSTH(context.Background())
	if err != nil {
		return fmt.Errorf("get STH: %w", err)
	}

	// get VCT public key and verify the STH signature
	pubKey, err := getPublicKey(vctClient)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	err = verifySTHSignature(sth, pubKey)
	if err != nil {
		return fmt.Errorf("failed to verify STH signature: %w", err)
	}

	logger.Debug("Verified STH signature", logfields.WithLogURLString(logMonitor.Log))

	err = c.verifySTH(logMonitor.Log, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH: %w", err)
	}

	logMonitor.STH = sth
	logMonitor.PubKey = pubKey

	// store the latest checked STH for log; set processing flag to false
	err = c.monitorStore.Update(logMonitor)
	if err != nil {
		return fmt.Errorf("failed to store STH: %w", err)
	}

	logger.Debug("Got latest tree size", logfields.WithLogURLString(logMonitor.Log), logfields.WithSizeUint64(sth.TreeSize))

	return nil
}

func (c *Client) verifySTH(logURL string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error { //nolint:cyclop
	var err error

	if storedSTH == nil {
		if sth.TreeSize == 0 {
			logger.Debug("Initial STH tree size is zero - nothing to do", logfields.WithLogURLString(logURL))

			return nil
		}

		if sth.TreeSize > c.maxTreeSize {
			logger.Debug("Initial STH tree size is greater than max size - nothing to do",
				logfields.WithLogURLString(logURL), logfields.WithSizeUint64(sth.TreeSize), logfields.WithMaxSizeUInt64(c.maxTreeSize))

			return nil
		}

		err = c.verifySTHTree(logURL, sth, vctClient)
		if err != nil {
			return fmt.Errorf("failed to verify STH tree: %w", err)
		}

		logger.Debug("Verified STH tree.", logfields.WithLogURLString(logURL))

		return nil
	}

	if sth.TreeSize == storedSTH.TreeSize && bytes.Equal(sth.SHA256RootHash, storedSTH.SHA256RootHash) {
		logger.Debug("STH tree size and root hash did not change - nothing to do",
			logfields.WithLogURLString(logURL), logfields.WithSizeUint64(sth.TreeSize))

		return nil
	}

	if sth.TreeSize < storedSTH.TreeSize ||
		(sth.TreeSize == storedSTH.TreeSize && !bytes.Equal(sth.SHA256RootHash, storedSTH.SHA256RootHash)) {
		logger.Error("Log tree size is less than stored tree size or root hashes are not equal",
			logfields.WithLogURLString(logURL), logfields.WithSizeUint64(sth.TreeSize),
			zap.Uint64("stored-size", storedSTH.TreeSize))

		e := c.processLogInconsistency(logURL, vctClient, sth)
		if e != nil {
			return fmt.Errorf("failed to process log inconsistency: %w", e)
		}

		return nil
	}

	err = c.verifySTHConsistency(logURL, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH consistency: %w", err)
	}

	logger.Debug("Verified STH consistency", logfields.WithLogURLString(logURL))

	return nil
}

func (c *Client) processLogInconsistency(logURL string, vctClient *vct.Client, sth *command.GetSTHResponse) error {
	// if storage is not enabled we have no record of missing objects so there's nothing else we can do
	if !c.entryStoreEnabled {
		return nil
	}

	logger.Info("Starting recovery process for log entry store ...", logfields.WithLogURLString(logURL))

	// entry storage is enabled - find last common entry for log and store
	index, entries, err := c.getDiscrepancyIndexAndAdditionalLogEntries(logURL, vctClient, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get discrepancy index and additional log entries: %w", err)
	}

	err = c.entryStore.FailLogEntriesFrom(logURL, uint64(index))
	if err != nil {
		return fmt.Errorf("failed to change log entry status to 'failed' for log entries starting from[%d]: %w",
			index, err)
	}

	if len(entries) == 0 {
		return nil
	}

	var dbEntries []command.LeafEntry
	for _, entry := range entries {
		dbEntries = append(dbEntries, *entry)
	}

	err = c.entryStore.StoreLogEntries(logURL, uint64(index), uint64(index)+uint64(len(entries)-1), dbEntries)
	if err != nil {
		return fmt.Errorf("failed to store additional log entries starting from[%d]: %w",
			index, err)
	}

	return nil
}

func (c *Client) getDiscrepancyIndexAndAdditionalLogEntries(logURL string,
	vctClient *vct.Client, treeSize uint64,
) (int64, []*command.LeafEntry, error) {
	var allDifferentLogEntries []*command.LeafEntry

	curEnd := int64(treeSize)

	for curEnd >= 0 {
		curStart := curEnd - int64(c.maxRecoveryFetchSize) + 1
		if curStart < 0 {
			curStart = 0
		}

		logEntries, err := c.getLogEntries(logURL, vctClient, uint64(curStart), uint64(curEnd), false)
		if err != nil {
			return 0, nil, fmt.Errorf("get log entries from[%d] to[%d]: %w", curStart, curEnd, err)
		}

		storedEntries, err := c.getStoreEntriesFrom(logURL, uint64(curStart), c.maxRecoveryFetchSize)
		if err != nil {
			return 0, nil, fmt.Errorf("get store entries from[%d]: %w", curStart, err)
		}

		minSize := minimum(len(storedEntries), len(logEntries))

		logger.Debug("Retrieved log entries from VCT and from storage",
			logfields.WithLogURLString(logURL), zap.Int("total-stored-entries", len(storedEntries)),
			zap.Int("total-entries", len(logEntries)),
			logfields.WithIndexUint64(uint64(curStart)), logfields.WithMaxSize(c.maxRecoveryFetchSize))

		for i := minSize - 1; i >= 0; i-- {
			if bytes.Equal(storedEntries[i].LeafInput, logEntries[i].LeafInput) {
				firstDifferentIndex := curStart + int64(i) + 1

				if i+1 < minSize {
					allDifferentLogEntries = append(logEntries[i+1:], allDifferentLogEntries...)
				}

				logger.Info("Found common log entry between store and log - first different index",
					logfields.WithLogURLString(logURL), logfields.WithIndexUint64(uint64(firstDifferentIndex)))

				return firstDifferentIndex, allDifferentLogEntries, nil
			}
		}

		allDifferentLogEntries = append(logEntries, allDifferentLogEntries...)

		curEnd = curStart - 1
	}

	logger.Info("There was no common log entry between store entries and log entries", logfields.WithLogURLString(logURL))

	// not found or zero index have same meaning, all current entries should be marked failed in the store and
	// all log entries should be added to the store
	return 0, allDifferentLogEntries, nil
}

func (c *Client) getStoreEntriesFrom(logURL string, start uint64, maxCount int) ([]*command.LeafEntry, error) {
	iter, err := c.entryStore.GetLogEntriesFrom(logURL, start)
	if err != nil {
		return nil, err
	}

	defer storeutil.CloseIterator(iter)

	n, err := iter.TotalItems()
	if err != nil {
		return nil, err
	}

	var retrievedEntries []*command.LeafEntry

	for i := 0; i < minimum(n, maxCount); i++ {
		val, err := iter.Next()
		if err != nil {
			return nil, err
		}

		retrievedEntries = append(retrievedEntries, val)
	}

	return retrievedEntries, nil
}

func minimum(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func (c *Client) verifySTHTree(logURL string, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	logger.Debug("Verifying STH tree consistency", logfields.WithLogURLString(logURL), logfields.WithSizeUint64(sth.TreeSize))

	entries, err := c.getAllEntries(logURL, vctClient, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("failed to get all entries: %w", err)
	}

	logger.Debug("Got all entries for tree", logfields.WithLogURLString(logURL), logfields.WithTotal(len(entries)),
		logfields.WithSizeUint64(sth.TreeSize))

	// Confirm that the tree made from the fetched entries produces the
	// same hash as that in the STH.
	root, err := c.logVerifier.GetRootHashFromEntries(entries)
	if err != nil {
		return fmt.Errorf("failed to get root hash from entries: %w", err)
	}

	if !bytes.Equal(root, sth.SHA256RootHash) {
		return fmt.Errorf("different root hash results from merkle tree building: %s and sth %s", root, sth.SHA256RootHash)
	}

	logger.Debug("Merkle tree hash from all entries matches latest STH", logfields.WithLogURLString(logURL))

	return nil
}

func (c *Client) getLogEntries(logURL string, vctClient *vct.Client, start, end uint64, store bool) ([]*command.LeafEntry, error) {
	var allEntries []*command.LeafEntry

	if start > end {
		return nil, fmt.Errorf("invalid range for get log entries[%d-%d]", start, end)
	}

	attempts := int(end-start)/c.maxGetEntriesRange + 1

	logger.Debug("Getting log entries (from-to) in attempts", logfields.WithLogURLString(logURL),
		logfields.WithFromIndexUint64(start), logfields.WithToIndexUint64(end), logfields.WithDeliveryAttempts(attempts))

	// fetch all the entries in the tree corresponding to the STH
	// VCT: get-entries allow maximum 1000 entries to be returned
	for i := 0; i < attempts; i++ {
		attemptStart := start + uint64(i*c.maxGetEntriesRange)
		attemptEnd := min(start+uint64((i+1)*c.maxGetEntriesRange-1), end)

		entries, err := vctClient.GetEntries(context.Background(), attemptStart, attemptEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to get entries for range[%d-%d]: %w", attemptStart, attemptEnd, err)
		}

		logger.Debug("Fetched entries (from-to)", logfields.WithLogURLString(logURL),
			logfields.WithFromIndexUint64(attemptStart), logfields.WithToIndexUint64(attemptEnd))

		if c.entryStoreEnabled && store {
			err = c.entryStore.StoreLogEntries(logURL, attemptStart, attemptEnd, entries.Entries)
			if err != nil {
				return nil, fmt.Errorf("failed to store entries for range[%d-%d]: %w", attemptStart, attemptEnd, err)
			}
		}

		for i := range entries.Entries {
			allEntries = append(allEntries, &entries.Entries[i])
		}
	}

	return allEntries, nil
}

func (c *Client) getAllEntries(logURL string, vctClient *vct.Client, treeSize uint64) ([]*command.LeafEntry, error) {
	return c.getLogEntries(logURL, vctClient, 0, treeSize-1, true)
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}

func (c *Client) verifySTHConsistency(logURL string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	if storedSTH.TreeSize > 0 {
		logger.Debug("Getting STH consistency for stored[%d] and latest[%d]",
			logfields.WithLogURLString(logURL), zap.Uint64("stored-size", storedSTH.TreeSize),
			logfields.WithSizeUint64(sth.TreeSize))

		sthConsistency, err := vctClient.GetSTHConsistency(context.Background(), storedSTH.TreeSize, sth.TreeSize)
		if err != nil {
			return fmt.Errorf("get STH consistency: %w", err)
		}

		logger.Debug("Found %d consistencies in STH consistency response", logfields.WithLogURLString(logURL),
			zap.Int("consistency-size", len(sthConsistency.Consistency)))

		err = c.logVerifier.VerifyConsistencyProof(int64(storedSTH.TreeSize), int64(sth.TreeSize),
			storedSTH.SHA256RootHash, sth.SHA256RootHash, sthConsistency.Consistency)
		if err != nil {
			return fmt.Errorf("verify consistency proof: %w", err)
		}
	} else {
		// any tree is consistent with tree size of zero - nothing to do
		logger.Debug("STH stored tree size is zero - nothing to do for STH consistency", logfields.WithLogURLString(logURL))
	}

	_, err := c.getLogEntries(logURL, vctClient, storedSTH.TreeSize, sth.TreeSize-1, true)
	if err != nil {
		return fmt.Errorf("get entries between trees: %w", err)
	}

	return nil
}

func getPublicKey(vctClient *vct.Client) ([]byte, error) {
	webResp, err := vctClient.Webfinger(context.Background())
	if err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}

	pubKeyRaw, ok := webResp.Properties[command.PublicKeyType]
	if !ok {
		return nil, fmt.Errorf("no public key")
	}

	pubKeyStr, ok := pubKeyRaw.(string)
	if !ok {
		return nil, fmt.Errorf("public key is not a string")
	}

	pubKey, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	return pubKey, nil
}

func verifySTHSignature(sth *command.GetSTHResponse, pubKey []byte) error {
	var sig *command.DigitallySigned

	err := json.Unmarshal(sth.TreeHeadSignature, &sig)
	if err != nil {
		return fmt.Errorf("unmarshal signature: %w", err)
	}

	kh, err := (&localkms.LocalKMS{}).PubKeyBytesToHandle(pubKey, sig.Algorithm.Type)
	if err != nil {
		return fmt.Errorf("pub key to handle: %w", err)
	}

	sigBytes, err := canonicalizer.MarshalCanonical(command.TreeHeadSignature{
		Version:        command.V1,
		SignatureType:  command.TreeHeadSignatureType,
		Timestamp:      sth.Timestamp,
		TreeSize:       sth.TreeSize,
		SHA256RootHash: sth.SHA256RootHash,
	})
	if err != nil {
		return fmt.Errorf("marshal TreeHeadSignature: %w", err)
	}

	return (&tinkcrypto.Crypto{}).Verify(sig.Signature, sigBytes, kh) //nolint: wrapcheck
}

// MonitorLogs will monitor logs for consistency.
func (c *Client) MonitorLogs() {
	logs, err := c.monitorStore.GetActiveLogs()
	if err != nil {
		if !errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Error("Failed to get active logs", log.WithError(err))
		}

		return
	}

	var wg sync.WaitGroup

	for _, log := range logs {
		wg.Add(1)

		go func(log *logmonitor.LogMonitor) {
			defer wg.Done()

			c.processLog(log)
		}(log)
	}

	wg.Wait()
}

func (c *Client) processLog(logMonitor *logmonitor.LogMonitor) {
	err := c.checkVCTConsistency(logMonitor)
	if err != nil {
		logger.Error("failed to check VCT consistency", logfields.WithLogURLString(logMonitor.Log), log.WithError(err))
	}
}

type noopLogEntryStore struct{}

func (s *noopLogEntryStore) StoreLogEntries(logURL string, start, end uint64, entries []command.LeafEntry) error {
	return nil
}

func (s *noopLogEntryStore) FailLogEntriesFrom(logURL string, start uint64) error {
	return nil
}

func (s *noopLogEntryStore) GetLogEntriesFrom(logURL string, start uint64) (logentry.EntryIterator, error) {
	return nil, nil
}
