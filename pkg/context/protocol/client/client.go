/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"fmt"
	"sort"

	"github.com/trustbloc/logutil-go/pkg/log"
	"github.com/trustbloc/sidetree-svc-go/pkg/api/protocol"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
)

var logger = log.New("protocol-client")

// Client implements protocol client.
type Client struct {
	protocols []protocol.Version
	current   protocol.Version
}

// Option is an option for client.
type Option func(opts *Client)

// WithCurrentProtocolVersion sets optional current protocol version (defaults to last registered protocol).
func WithCurrentProtocolVersion(version string) Option {
	return func(opts *Client) {
		for _, p := range opts.protocols {
			if p.Version() == version {
				opts.current = p

				return
			}
		}
	}
}

// New creates new protocol client.
func New(protocolVersions []protocol.Version, opts ...Option) (*Client, error) {
	if len(protocolVersions) == 0 {
		return nil, fmt.Errorf("must provide at least one protocol version")
	}

	// Creating the list of the protocol versions
	var protocols []protocol.Version

	protocols = append(protocols, protocolVersions...)

	// Sorting the protocolParameter list based on protocol genesis time
	sort.SliceStable(protocols, func(i, j int) bool {
		return protocols[j].Protocol().GenesisTime > protocols[i].Protocol().GenesisTime
	})

	client := &Client{
		protocols: protocols,
		current:   protocols[len(protocols)-1],
	}

	// apply options
	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Current returns the latest version of protocol.
func (c *Client) Current() (protocol.Version, error) {
	return c.current, nil
}

// Get gets protocol version based on blockchain(transaction) time.
func (c *Client) Get(genesisTime uint64) (protocol.Version, error) {
	for i := len(c.protocols) - 1; i >= 0; i-- {
		pv := c.protocols[i]
		p := pv.Protocol()

		logger.Debug("Checking protocol for genesis time...", logfields.WithGenesisTime(genesisTime),
			logfields.WithSidetreeProtocol(&p))

		if genesisTime == p.GenesisTime {
			logger.Debug("Found protocol for version genesis time", logfields.WithGenesisTime(genesisTime),
				logfields.WithSidetreeProtocol(&p))

			return pv, nil
		}
	}

	return nil, fmt.Errorf("protocol parameters are not defined for version genesis time: %d", genesisTime)
}
