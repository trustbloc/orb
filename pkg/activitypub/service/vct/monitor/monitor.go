/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/trillian/merkle/logverifier"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
)

var logger = log.New("vct-consistency-monitor")

// VCT limits maximum number of entries to 1000.
const maxGetEntriesRange = 1000

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type logMonitorStore interface {
	GetActiveLogs() ([]*logmonitor.LogMonitor, error)
	Update(log *logmonitor.LogMonitor) error
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
	store logMonitorStore
	http  httpClient
}

// New returns VCT consistency monitoring client.
func New(store logMonitorStore, httpClient httpClient) (*Client, error) {
	client := &Client{
		store: store,
		http:  httpClient,
	}

	return client, nil
}

func (c *Client) checkVCTConsistency(logMonitor *logmonitor.LogMonitor) error {
	logger.Debugf("log[%s]: checking VCT consistency...", logMonitor.Log)

	storedSTH := logMonitor.STH

	// creates new client based on domain
	vctClient := vct.New(logMonitor.Log, vct.WithHTTPClient(c.http))

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

	err = verifySTH(logMonitor.Log, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH: %w", err)
	}

	logMonitor.Processing = false
	logMonitor.STH = sth
	logMonitor.PubKey = pubKey

	// store the latest checked STH for domain; set processing flag to false
	err = c.store.Update(logMonitor)
	if err != nil {
		return fmt.Errorf("failed to store STH: %w", err)
	}

	logger.Debugf("log[%s]: latest tree size[%d]", logMonitor.Log, sth.TreeSize)

	return nil
}

func verifySTH(logURL string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	var err error

	if storedSTH == nil {
		if sth.TreeSize == 0 {
			logger.Debugf("log[%s]: initial STH tree size is zero - nothing to do", logURL)

			return nil
		}

		err = verifySTHTree(logURL, sth, vctClient)
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

	err = verifySTHConsistency(logURL, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH consistency: %w", err)
	}

	logger.Debugf("log[%s]: verified STH consistency", logURL)

	return nil
}

func verifySTHTree(domain string, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	logger.Debugf("log[%s]: get STH tree[%d] and verify consistency", domain, sth.TreeSize)

	entries, err := getEntries(domain, vctClient, sth.TreeSize, maxGetEntriesRange)
	if err != nil {
		return fmt.Errorf("failed to get all entries: %w", err)
	}

	logger.Debugf("log[%s]: get all entries[%d] for tree size[%d]", domain, len(entries), sth.TreeSize)

	// Confirm that the tree made from the fetched entries produces the
	// same hash as that in the STH.
	root, err := getRootHashFromEntries(entries)
	if err != nil {
		return fmt.Errorf("failed to get root hash from entries: %w", err)
	}

	if !bytes.Equal(root, sth.SHA256RootHash) {
		return fmt.Errorf("different root hash results from merkle tree building: %s and sth %s", root, sth.SHA256RootHash)
	}

	logger.Debugf("log[%s]: merkle tree hash from all entries matches latest STH", domain)

	return nil
}

func getEntries(domain string, vctClient *vct.Client,
	treeSize uint64, maxEntriesPerRequest int) ([]*command.LeafEntry, error) {
	var allEntries []*command.LeafEntry

	attempts := int(treeSize-1) / maxEntriesPerRequest

	// fetch all the entries in the tree corresponding to the STH
	// VCT: get-entries allow maximum 1000 entries to be returned
	for i := 0; i <= attempts; i++ {
		start := uint64(i * maxEntriesPerRequest)
		end := min(uint64((i+1)*maxEntriesPerRequest-1), treeSize-1)

		entries, err := vctClient.GetEntries(context.Background(), start, end)
		if err != nil {
			return nil, fmt.Errorf("failed to get entries for range[%d-%d]: %w", start, end, err)
		}

		logger.Debugf("domain[%s] fetched entries from %d to %d", domain, start, end)

		for i := range entries.Entries {
			allEntries = append(allEntries, &entries.Entries[i])
		}
	}

	return allEntries, nil
}

func getRootHashFromEntries(entries []*command.LeafEntry) ([]byte, error) {
	hasher := rfc6962.DefaultHasher
	fact := compact.RangeFactory{Hash: hasher.HashChildren}
	cr := fact.NewEmptyRange(0)

	// We don't simply iterate the map, as we need to preserve the leaves order.
	for _, entry := range entries {
		err := cr.Append(hasher.HashLeaf(entry.LeafInput), nil)
		if err != nil {
			return nil, err
		}
	}

	root, err := cr.GetRootHash(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to compute compact range root: %w", err)
	}

	return root, nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}

	return b
}

func verifySTHConsistency(domain string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	if storedSTH.TreeSize == 0 {
		// any tree is consistent with tree size of zero - nothing to do
		logger.Debugf("log[%s]: STH stored tree size is zero - nothing to do for STH consistency", domain)

		return nil
	}

	logger.Debugf("log[%s]: get STH consistency for stored[%d] and latest[%d]",
		domain, storedSTH.TreeSize, sth.TreeSize)

	sthConsistency, err := vctClient.GetSTHConsistency(context.Background(), storedSTH.TreeSize, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("get STH consistency: %w", err)
	}

	logger.Debugf("log[%s]: found %d consistencies in STH consistency response",
		domain, len(sthConsistency.Consistency))

	logVerifier := logverifier.New(rfc6962.DefaultHasher)

	err = logVerifier.VerifyConsistencyProof(int64(storedSTH.TreeSize), int64(sth.TreeSize),
		storedSTH.SHA256RootHash, sth.SHA256RootHash, sthConsistency.Consistency)
	if err != nil {
		return fmt.Errorf("verify consistency proof: %w", err)
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
	logs, err := c.store.GetActiveLogs()
	if err != nil {
		if errors.Is(err, orberrors.ErrContentNotFound) {
			logger.Infof("no active log monitors found - nothing to do")
		} else {
			logger.Errorf("failed to get active logs: %s", err.Error())
		}

		return
	}

	for _, log := range logs {
		go func(log *logmonitor.LogMonitor) {
			c.processLog(log)
		}(log)
	}
}

func (c *Client) processLog(logMonitor *logmonitor.LogMonitor) {
	if logMonitor.Processing {
		logger.Debugf("log[%s]: previous run is still processing - waiting for next cycle", logMonitor.Log)

		return
	}

	logMonitor.Processing = true

	err := c.store.Update(logMonitor)
	if err != nil {
		logger.Errorf("log[%s]: failed to update log monitor processing flag to true: %s", logMonitor.Log, err.Error())

		return
	}

	if err := c.checkVCTConsistency(logMonitor); err != nil {
		logger.Errorf("[%s] failed to check VCT consistency: %s", logMonitor.Log, err.Error())

		logMonitor.Processing = false

		err := c.store.Update(logMonitor)
		if err != nil {
			logger.Errorf("log[%s]: failed to update log monitor processing flag to false: %s", logMonitor.Log, err.Error())
		}

		return
	}
}
