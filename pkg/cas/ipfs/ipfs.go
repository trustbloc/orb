/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ipfs

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"time"

	"github.com/bluele/gcache"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/hashlink"
	"github.com/trustbloc/orb/pkg/multihash"
)

var logger = log.New("cas-ipfs")

const (
	defaultCacheSize = 1000
	casType          = "ipfs"
)

type metricsProvider interface {
	CASIncrementCacheHitCount()
	CASReadTime(casType string, value time.Duration)
}

// Client will write new documents to IPFS and read existing documents from IPFS based on CID.
// It implements Sidetree CAS interface.
type Client struct {
	ipfs    *shell.Shell
	opts    []extendedcasclient.CIDFormatOption
	hl      *hashlink.HashLink
	cache   gcache.Cache
	metrics metricsProvider
}

// New creates cas client.
// If no CID version is specified, then v1 will be used by default.
func New(url string, timeout time.Duration, cacheSize int, metrics metricsProvider,
	opts ...extendedcasclient.CIDFormatOption) *Client {
	ipfs := shell.NewShell(url)

	ipfs.SetTimeout(timeout)

	if cacheSize == 0 {
		cacheSize = defaultCacheSize
	}

	c := &Client{ipfs: ipfs, opts: opts, hl: hashlink.New(), metrics: metrics}

	c.cache = gcache.New(cacheSize).LoaderFunc(func(key interface{}) (interface{}, error) {
		cid, err := c.get(key.(string))
		if err != nil {
			return nil, err
		}

		logger.Debugf("Cached content for CID [%s]", cid)

		return cid, nil
	}).Build()

	return c
}

// Write writes the given content to IPFS.
// Returns the address (CID) of the content.
func (m *Client) Write(content []byte) (string, error) {
	cid, err := m.WriteWithCIDFormat(content, m.opts...)
	if err != nil {
		return "", err
	}

	links := []string{"ipfs://" + cid}

	hl, err := m.hl.CreateHashLink(content, links)
	if err != nil {
		return "", fmt.Errorf("failed to create hashlink for ipfs: %w", err)
	}

	return hl, nil
}

// WriteWithCIDFormat writes the given content to IPFS using the provided CID format options.
// Returns the address (CID) of the content.
// TODO (#443): Support v1 CID formats (different multibases and multicodecs) other than just the IPFS default.
func (m *Client) WriteWithCIDFormat(content []byte, opts ...extendedcasclient.CIDFormatOption) (string, error) {
	options, err := getOptions(opts)
	if err != nil {
		return "", err
	}

	var v1AddOpt []shell.AddOpts

	if options.CIDVersion == 1 {
		v1AddOpt = []shell.AddOpts{shell.CidVersion(1)}
	}

	cid, err := m.ipfs.Add(bytes.NewReader(content), v1AddOpt...)
	if err != nil {
		if strings.Contains(err.Error(), "command not found") {
			return "", fmt.Errorf("%w. (Does this IPFS node support writes?)", err)
		}

		return "", orberrors.NewTransient(err)
	}

	logger.Debugf("ipfs added content returned cid: %s", cid)

	return cid, nil
}

// GetPrimaryWriterType returns primary writer type.
func (m *Client) GetPrimaryWriterType() string {
	return "ipfs"
}

// Read reads the content for the given CID from CAS.
// returns the contents of CID.
func (m *Client) Read(cidOrHash string) ([]byte, error) {
	logger.Debugf("read cid or hash from ipfs: %s", cidOrHash)

	cid, err := m.getCID(cidOrHash)
	if err != nil {
		return nil, fmt.Errorf("value[%s] passed to ipfs reader is not CID and cannot be converted to CID: %w", cidOrHash, err) //nolint:lll
	}

	if m.cache.Has(cid) {
		m.metrics.CASIncrementCacheHitCount()
	}

	content, err := m.cache.Get(cid)
	if err != nil {
		return nil, err
	}

	return content.([]byte), nil
}

func (m *Client) get(cid string) ([]byte, error) {
	startTime := time.Now()

	defer func() {
		m.metrics.CASReadTime(casType, time.Since(startTime))
	}()

	reader, err := m.ipfs.Cat(cid)
	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			return nil, orberrors.NewTransient(fmt.Errorf("%s: %w", err.Error(), orberrors.ErrContentNotFound))
		}

		return nil, orberrors.NewTransient(err)
	}

	defer closeAndLog(reader)

	return ioutil.ReadAll(reader)
}

func (m *Client) getCID(cidOrHash string) (string, error) {
	cid := cidOrHash

	if strings.HasPrefix(cidOrHash, hashlink.HLPrefix) {
		hashlinkInfo, err := m.hl.ParseHashLink(cidOrHash)
		if err != nil {
			return "", fmt.Errorf("failed to parse hash link in ipfs client: %w", err)
		}

		cid = hashlinkInfo.ResourceHash
	}

	if !multihash.IsValidCID(cid) {
		var err error

		cid, err = m.getCIDFromHash(cid)
		if err != nil {
			return "", fmt.Errorf("failed to get cid in ipfs reader: %w", err)
		}

		logger.Debugf("converted value[%s] to CID: %s", cidOrHash, cid)
	}

	return cid, nil
}

func (m *Client) getCIDFromHash(hash string) (string, error) {
	options, err := getOptions(m.opts)
	if err != nil {
		return "", err
	}

	var cid string

	switch options.CIDVersion {
	case 0:
		cid, err = multihash.ToV0CID(hash)
		if err != nil {
			return "", fmt.Errorf("value[%s] cannot be converted to V0 CID: %w", hash, err)
		}
	case 1:
		cid, err = multihash.ToV1CID(hash)
		if err != nil {
			return "", fmt.Errorf("value[%s] cannot be converted to V1 CID: %w", hash, err)
		}
	default:
		return "", fmt.Errorf("cid version[%d] not supported", options.CIDVersion)
	}

	return cid, nil
}

func getOptions(opts []extendedcasclient.CIDFormatOption) (
	extendedcasclient.CIDFormatOptions, error) {
	options := extendedcasclient.CIDFormatOptions{CIDVersion: 1}

	for _, option := range opts {
		if option != nil {
			option(&options)
		}
	}

	if options.CIDVersion != 0 && options.CIDVersion != 1 {
		return extendedcasclient.CIDFormatOptions{},
			fmt.Errorf("%d is not a supported CID version. It must be either 0 or 1", options.CIDVersion)
	}

	return options, nil
}

func closeAndLog(rc io.Closer) {
	if err := rc.Close(); err != nil {
		logger.Warnf("failed to close reader: %s", err.Error())
	}
}
