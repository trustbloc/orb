/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cas

import (
	"bytes"
	"io"
	"io/ioutil"

	shell "github.com/ipfs/go-ipfs-api"
	log "github.com/sirupsen/logrus"
)

// Client will write new documents to IPFS and read existing documents from IPFS based on CID.
// It implements Sidetree CAS interface.
type Client struct {
	ipfs *shell.Shell
}

// New creates cas client.
func New(url string) *Client {
	ipfs := shell.NewShell(url)

	return &Client{ipfs: ipfs}
}

// Write writes the given content to CAS.
// returns cid which represents the address of the content.
func (m *Client) Write(content []byte) (string, error) {
	cid, err := m.ipfs.Add(bytes.NewReader(content))
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
		return nil, err
	}

	defer close(reader)

	return ioutil.ReadAll(reader)
}

func close(rc io.Closer) {
	if err := rc.Close(); err != nil {
		log.Warnf("failed to close reader: %s", err.Error())
	}
}
