/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontextrest

import (
	"fmt"
	"net/http"

	cmdcontext "github.com/hyperledger/aries-framework-go/pkg/controller/command/jsonld/context"
	ldctxrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/jsonld/context"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
)

type storageProviderFn func() storage.Provider

func (spf storageProviderFn) StorageProvider() storage.Provider { return spf() }

// New returns a handler implementation for the service.
func New(p storage.Provider) (*Client, error) {
	ctxCmd, err := cmdcontext.New(storageProviderFn(func() storage.Provider { return p }))
	if err != nil {
		return nil, fmt.Errorf("new cmd context: %w", err)
	}

	return &Client{ctxCmd: ctxCmd}, nil
}

// Client represents a handler for adding ldcontext.
type Client struct {
	*resthandler.AuthHandler
	ctxCmd *cmdcontext.Command
}

// Path returns the HTTP REST endpoint for the service.
func (c *Client) Path() string {
	return ldctxrest.AddContextPath
}

// Method returns the HTTP REST method for the service.
func (c *Client) Method() string {
	return http.MethodPost
}

// Handler returns the HTTP REST handler for the WebCAS service.
func (c *Client) Handler() common.HTTPRequestHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		err := c.ctxCmd.Add(w, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error())) // nolint: errcheck, gosec
		}
	}
}
