/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962/hasher"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"
)

var logger = log.New("vct-consistency-monitor")

const (
	storeName = "vct-consistency-monitor"
)

// httpClient represents HTTP client.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
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
	store   storage.Store
	http    httpClient
	domains []string
}

// New returns VCT consistency monitoring client.
func New(domains []string, provider storage.Provider, httpClient httpClient) (*Client, error) {
	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	err = provider.SetStoreConfig(storeName, storage.StoreConfiguration{})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	client := &Client{
		store:   store,
		http:    httpClient,
		domains: domains,
	}

	return client, nil
}

func (c *Client) checkVCTConsistency(domain string) error {
	logger.Debugf("domain[%s]: checking VCT consistency...", domain)

	var storedSTH *command.GetSTHResponse

	storedSTHBytes, err := c.store.Get(domain)
	if err != nil && !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("get current STH from store: %w", err)
	}

	if err == nil {
		if err = json.Unmarshal(storedSTHBytes, &storedSTH); err != nil {
			return fmt.Errorf("unmarshal entity: %w", err)
		}
	}

	// creates new client based on domain
	vctClient := vct.New(domain, vct.WithHTTPClient(c.http))

	// gets the latest signed tree head and compare to stored one
	sth, err := vctClient.GetSTH(context.Background())
	if err != nil {
		return fmt.Errorf("get STH: %w", err)
	}

	// get VCT public key and verify the STH signature
	err = verifySTHSignature(sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH signature: %w", err)
	}

	logger.Debugf("domain[%s]: verified STH signature", domain)

	err = verifySTH(domain, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH signature: %w", err)
	}

	sthBytes, err := json.Marshal(sth)
	if err != nil {
		return fmt.Errorf("marshal latest STH: %w", err)
	}

	// store the latest checked STH for domain
	err = c.store.Put(domain, sthBytes)
	if err != nil {
		return fmt.Errorf("store STH: %w", err)
	}

	logger.Debugf("domain[%s]: new tree size[%d], stored STH:", domain, sth.TreeSize, string(sthBytes))

	return nil
}

func verifySTH(domain string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	var err error

	if storedSTH == nil {
		if sth.TreeSize == 0 {
			logger.Debugf("domain[%s]: initial STH tree size is zero - nothing to do", domain)

			return nil
		}

		err = verifySTHTree(domain, sth)
		if err != nil {
			return fmt.Errorf("failed to verify STH tree: %w", err)
		}

		logger.Debugf("domain[%s]: verified STH tree", domain)

		return nil
	}

	if sth.TreeSize == storedSTH.TreeSize {
		logger.Debugf("domain[%s]: STH tree size[%d] did not change - nothing to do", domain, sth.TreeSize)

		return nil
	}

	err = verifySTHConsistency(domain, storedSTH, sth, vctClient)
	if err != nil {
		return fmt.Errorf("failed to verify STH consistency: %w", err)
	}

	logger.Debugf("domain[%s]: verified STH consistency", domain)

	return nil
}

// nolint: unparam
func verifySTHTree(domain string, sth *command.GetSTHResponse) error {
	logger.Debugf("domain[%s]: get STH tree[%d] and verify consistency", domain, sth.TreeSize)

	// TODO: Fetch all the entries in the tree corresponding to the STH
	// Confirm that the tree made from the fetched entries produces the
	// same hash as that in the STH.

	return nil
}

func verifySTHConsistency(domain string, storedSTH, sth *command.GetSTHResponse, vctClient *vct.Client) error {
	if storedSTH.TreeSize == 0 {
		// any tree is consistent with tree size of zero - nothing to do
		logger.Debugf("domain[%s]: STH stored tree size[%d] is zero - nothing to do for STH consistency",
			domain, sth.TreeSize)

		return nil
	}

	logger.Debugf("domain[%s]: get STH consistency for stored[%d] and latest[%d]",
		domain, storedSTH.TreeSize, sth.TreeSize)

	sthConsistency, err := vctClient.GetSTHConsistency(context.Background(), storedSTH.TreeSize, sth.TreeSize)
	if err != nil {
		return fmt.Errorf("get STH consistency: %w", err)
	}

	logger.Debugf("domain[%s]: found %d consistencies in STH consistency response",
		domain, len(sthConsistency.Consistency))

	logVerifier := logverifier.New(hasher.DefaultHasher)

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

func verifySTHSignature(sth *command.GetSTHResponse, vctClient *vct.Client) error {
	pubKey, err := getPublicKey(vctClient)
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}

	var sig *command.DigitallySigned

	err = json.Unmarshal(sth.TreeHeadSignature, &sig)
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

// CheckVCTConsistency will check VCT consistency.
func (c *Client) CheckVCTConsistency() {
	for _, d := range c.domains {
		go func(domain string) {
			if err := c.checkVCTConsistency(domain); err != nil {
				logger.Errorf("[%s] %s", domain, err.Error())
			}
		}(d)
	}
}
