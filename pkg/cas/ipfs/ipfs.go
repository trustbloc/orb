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

	shell "github.com/ipfs/go-ipfs-api"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/orb/pkg/cas/extendedcasclient"
	"github.com/trustbloc/orb/pkg/store/cas"
)

const timeout = 2

// Client will write new documents to IPFS and read existing documents from IPFS based on CID.
// It implements Sidetree CAS interface.
type Client struct {
	ipfs *shell.Shell
	opts []extendedcasclient.CIDFormatOption
}

// New creates cas client.
// If no CID version is specified, then v1 will be used by default.
func New(url string, opts ...extendedcasclient.CIDFormatOption) *Client {
	ipfs := shell.NewShell(url)

	ipfs.SetTimeout(timeout * time.Second)

	return &Client{ipfs: ipfs, opts: opts}
}

// Write writes the given content to IPFS.
// Returns the address (CID) of the content.
func (m *Client) Write(content []byte) (string, error) {
	return m.WriteWithCIDFormat(content, m.opts...)
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
		return "", err
	}

	log.Debugf("added content returned cid: %s", cid)

	return cid, nil
}

// Read reads the content for the given CID from CAS.
// returns the contents of CID.
func (m *Client) Read(cid string) ([]byte, error) {
	reader, err := m.ipfs.Cat(cid)
	if err != nil {
		if strings.Contains(err.Error(), "context deadline exceeded") {
			return nil, fmt.Errorf("%s: %w", err.Error(), cas.ErrContentNotFound)
		}

		return nil, err
	}

	defer closeAndLog(reader)

	return ioutil.ReadAll(reader)
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
		log.Warnf("failed to close reader: %s", err.Error())
	}
}
