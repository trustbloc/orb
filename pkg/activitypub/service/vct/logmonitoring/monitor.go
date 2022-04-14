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
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/activitypub/service/vct/logmonitoring/verifier"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

var logger = log.New("vct-consistency-monitor")

const (
	// VCT limits maximum number of entries to 1000.
	defaultMaxGetEntriesRange = 1000

	// maximum in-memory tree size.
	defaultMaxTreeSize = 10000

	vctReadTokenKey  = "vct-read"
	vctWriteTokenKey = "vct-write"
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
	logVerifier        logVerifier
	monitorStore       logMonitorStore
	entryStore         logEntryStore
	http               httpClient
	requestTokens      map[string]string
	maxTreeSize        uint64
	maxGetEntriesRange int
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

// WithLogEntriesStore sets optional implementation of log entries store (default is noop store).
func WithLogEntriesStore(s logEntryStore) Option {
	return func(opts *Client) {
		opts.entryStore = s
	}
}

// New returns new client for monitoring VCT log consistency.
func New(store logMonitorStore, httpClient httpClient, requestTokens map[string]string, opts ...Option) (*Client, error) { //nolint:lll
	client := &Client{
		logVerifier:        verifier.New(),
		monitorStore:       store,
		entryStore:         &noopLogEntryStore{},
		http:               httpClient,
		requestTokens:      requestTokens,
		maxTreeSize:        defaultMaxTreeSize,
		maxGetEntriesRange: defaultMaxGetEntriesRange,
	}

	// apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func (c *Client) checkVCTConsistency(logMonitor *logmonitor.LogMonitor) error {
	logger.Debugf("log[%s]: checking VCT consistency...", logMonitor.Log)

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

	logger.Debugf("log[%s]: verified STH signature", logMonitor.Log)

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

	logger.Debugf("log[%s]: latest tree size[%d]", logMonitor.Log, sth.TreeSize)

	return nil
}

func (c *Client) verifySTH(logURL string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	var err error

	if storedSTH == nil {
		if sth.TreeSize == 0 {
			logger.Debugf("log[%s]: initial STH tree size is zero - nothing to do", logURL)

			return nil
		}

		if sth.TreeSize > c.maxTreeSize {
			logger.Debugf("log[%s]: initial STH tree size[%d] is greater than max size[%d] - nothing to do",
				logURL, sth.TreeSize, c.maxTreeSize)

			return nil
		}

		err = c.verifySTHTree(logURL, sth, vctClient)
		if err != nil {
			return fmt.Errorf("failed to verify STH tree: %w", err)
		}

		logger.Debugf("log[%s]: verified STH tree", logURL)

		return nil
	}

	if sth.TreeSize == storedSTH.TreeSize {
		logger.Debugf("log[%s]: STH tree size[%d] did not change - nothing to do", logURL, sth.TreeSize)

		return nil
	}

	err = c.verifySTHConsistency(logURL, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH consistency: %w", err)
	}

	logger.Debugf("log[%s]: verified STH consistency", logURL)

	return nil
}

func (c *Client) verifySTHTree(logURL string, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	logger.Debugf("log[%s]: get STH tree[%d] and verify consistency", logURL, sth.TreeSize)

	entries, err := c.getAllEntries(logURL, vctClient, sth.TreeSize, c.maxGetEntriesRange)
	if err != nil {
		return fmt.Errorf("failed to get all entries: %w", err)
	}

	logger.Debugf("log[%s]: get all entries[%d] for tree size[%d]", logURL, len(entries), sth.TreeSize)

	// Confirm that the tree made from the fetched entries produces the
	// same hash as that in the STH.
	root, err := c.logVerifier.GetRootHashFromEntries(entries)
	if err != nil {
		return fmt.Errorf("failed to get root hash from entries: %w", err)
	}

	if !bytes.Equal(root, sth.SHA256RootHash) {
		return fmt.Errorf("different root hash results from merkle tree building: %s and sth %s", root, sth.SHA256RootHash)
	}

	logger.Debugf("log[%s]: merkle tree hash from all entries matches latest STH", logURL)

	return nil
}

func (c *Client) getEntries(logURL string, vctClient *vct.Client,
	start, end uint64, maxEntriesPerRequest int) ([]*command.LeafEntry, error) {
	var allEntries []*command.LeafEntry

	attempts := int(end) / maxEntriesPerRequest

	// fetch all the entries in the tree corresponding to the STH
	// VCT: get-entries allow maximum 1000 entries to be returned
	for i := 0; i <= attempts; i++ {
		attemptStart := start + uint64(i*maxEntriesPerRequest)
		attemptEnd := min(uint64((i+1)*maxEntriesPerRequest-1), end)

		entries, err := vctClient.GetEntries(context.Background(), attemptStart, attemptEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to get entries for range[%d-%d]: %w", attemptStart, attemptEnd, err)
		}

		logger.Debugf("log[%s] fetched entries from %d to %d", logURL, attemptStart, attemptEnd)

		err = c.entryStore.StoreLogEntries(logURL, attemptStart, attemptEnd, entries.Entries)
		if err != nil {
			return nil, fmt.Errorf("failed to store entries for range[%d-%d]: %w", attemptStart, attemptEnd, err)
		}

		for i := range entries.Entries {
			allEntries = append(allEntries, &entries.Entries[i])
		}
	}

	return allEntries, nil
}

func (c *Client) getAllEntries(logURL string, vctClient *vct.Client,
	treeSize uint64, maxEntriesPerRequest int) ([]*command.LeafEntry, error) {
	return c.getEntries(logURL, vctClient, 0, treeSize-1, maxEntriesPerRequest)
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}

func (c *Client) verifySTHConsistency(logURL string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error { //nolint:lll
	if storedSTH.TreeSize == 0 {
		// any tree is consistent with tree size of zero - nothing to do
		logger.Debugf("log[%s]: STH stored tree size is zero - nothing to do for STH consistency", logURL)

		return nil
	}

	logger.Debugf("log[%s]: get STH consistency for stored[%d] and latest[%d]",
		logURL, storedSTH.TreeSize, sth.TreeSize)

	sthConsistency, err := vctClient.GetSTHConsistency(context.Background(), storedSTH.TreeSize, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("get STH consistency: %w", err)
	}

	logger.Debugf("log[%s]: found %d consistencies in STH consistency response",
		logURL, len(sthConsistency.Consistency))

	err = c.logVerifier.VerifyConsistencyProof(int64(storedSTH.TreeSize), int64(sth.TreeSize),
		storedSTH.SHA256RootHash, sth.SHA256RootHash, sthConsistency.Consistency)
	if err != nil {
		return fmt.Errorf("verify consistency proof: %w", err)
	}

	_, err = c.getEntries(logURL, vctClient, storedSTH.TreeSize, sth.TreeSize-1, c.maxGetEntriesRange)
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

	sigBytes, err := json.Marshal(command.TreeHeadSignature{
		Version:        command.V1,
		SignatureType:  command.TreeHeadSignatureType,
		Timestamp:      sth.Timestamp,
		TreeSize:       sth.TreeSize,
		SHA256RootHash: sth.SHA256RootHash,
	})
	if err != nil {
		return fmt.Errorf("marshal TreeHeadSignature: %w", err)
	}

	return (&tinkcrypto.Crypto{}).Verify(sig.Signature, sigBytes, kh) // nolint: wrapcheck
}

// MonitorLogs will monitor logs for consistency.
func (c *Client) MonitorLogs() {
	logger.Debugf("start log monitoring...")

	logs, err := c.monitorStore.GetActiveLogs()
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Debugf("no active log monitors found - nothing to do")
		} else {
			logger.Errorf("failed to get active logs: %s", err.Error())
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

	logger.Debugf("completed log monitoring...")
}

func (c *Client) processLog(logMonitor *logmonitor.LogMonitor) {
	err := c.checkVCTConsistency(logMonitor)
	if err != nil {
		logger.Errorf("[%s] failed to check VCT consistency: %s", logMonitor.Log, err.Error())
	}
}

type noopLogEntryStore struct{}

func (s *noopLogEntryStore) StoreLogEntries(logURL string, start, end uint64, entries []command.LeafEntry) error {
	return nil
}
