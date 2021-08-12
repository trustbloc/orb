/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontextrest

import (
	"fmt"
	"net/http"

	ldcmd "github.com/hyperledger/aries-framework-go/pkg/controller/command/ld"
	ldrest "github.com/hyperledger/aries-framework-go/pkg/controller/rest/ld"
	ldsvc "github.com/hyperledger/aries-framework-go/pkg/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
)

type storageProviderFn func() storage.Provider

func (spf storageProviderFn) StorageProvider() storage.Provider { return spf() }

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

// New returns a handler implementation for the service.
func New(p storage.Provider) (*Client, error) {
	storageProvider := storageProviderFn(func() storage.Provider { return p })()

	contextStore, err := ldstore.NewContextStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(storageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	return &Client{ctxCmd: ldcmd.New(ldsvc.New(ldStore))}, nil
}

// Client represents a handler for adding ldcontext.
type Client struct {
	*resthandler.AuthHandler
	ctxCmd *ldcmd.Command
}

// Path returns the HTTP REST endpoint for the service.
func (c *Client) Path() string {
	return ldrest.AddContextsPath
}

// Method returns the HTTP REST method for the service.
func (c *Client) Method() string {
	return http.MethodPost
}

// Handler returns the HTTP REST handler for the WebCAS service.
func (c *Client) Handler() common.HTTPRequestHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		err := c.ctxCmd.AddContexts(w, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error())) // nolint: errcheck, gosec
		}
	}
}
