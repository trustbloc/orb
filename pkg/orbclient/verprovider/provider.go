/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verprovider

import (
	"fmt"
	"sort"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/context/common"
)

var logger = log.New("client-version-provider")

// ClientVersionProvider implements client versions.
type ClientVersionProvider struct {
	versions []common.ClientVersion
}

// New creates new client version provider.
func New(clientVersions []common.ClientVersion) *ClientVersionProvider {
	// Creating the list of the client versions
	var versions []common.ClientVersion

	versions = append(versions, clientVersions...)

	// Sorting the client version list based on version genesis time
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[j].Protocol().GenesisTime > versions[i].Protocol().GenesisTime
	})

	return &ClientVersionProvider{
		versions: versions,
	}
}

// Current returns the latest version of client.
func (c *ClientVersionProvider) Current() (common.ClientVersion, error) {
	latest := len(c.versions) - 1

	return c.versions[latest], nil
}

// Get gets client version based on version time.
func (c *ClientVersionProvider) Get(versionTime uint64) (common.ClientVersion, error) {
	logger.Debugf("available client versions: %s", c.versions)

	for i := len(c.versions) - 1; i >= 0; i-- {
		cv := c.versions[i]
		p := cv.Protocol()

		logger.Debugf("checking client version for version genesis time %d: %+v", versionTime, p)

		if versionTime >= p.GenesisTime {
			logger.Debugf("found client version for version genesis time %d: %+v", versionTime, p)

			return cv, nil
		}
	}

	return nil, fmt.Errorf("client version is not defined for version genesis time: %d", versionTime)
}
