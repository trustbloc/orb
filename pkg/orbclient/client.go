/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package orbclient

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/orb/pkg/orbclient/nsprovider"
	"github.com/trustbloc/orb/pkg/orbclient/verprovider"
	"github.com/trustbloc/orb/pkg/protocolversion/clientregistry"
)

var logger = log.New("orb-client")

// OrbClient implements Orb client.
type OrbClient struct {
	nsProvider        namespaceProvider
	publicKeyFetcher  verifiable.PublicKeyFetcher
	docLoader         ld.DocumentLoader
	casReader         common.CASReader
	disableProofCheck bool
}

type namespaceProvider interface {
	ForNamespace(namespace string) (nsprovider.ClientVersionProvider, error)
}

// Option is an option for document handler.
type Option func(opts *OrbClient)

// WithPublicKeyFetcher sets optional public key fetcher.
func WithPublicKeyFetcher(pkf verifiable.PublicKeyFetcher) Option {
	return func(opts *OrbClient) {
		opts.publicKeyFetcher = pkf
	}
}

// WithJSONLDDocumentLoader sets optional document loader.
func WithJSONLDDocumentLoader(docLoader ld.DocumentLoader) Option {
	return func(opts *OrbClient) {
		opts.docLoader = docLoader
	}
}

// WithDisableProofCheck sets optional disable proof check flag.
func WithDisableProofCheck(disableProofCheck bool) Option {
	return func(opts *OrbClient) {
		opts.disableProofCheck = disableProofCheck
	}
}

// New creates new Orb client.
func New(namespace string, cas common.CASReader, opts ...Option) (*OrbClient, error) {
	versions := []string{"1.0"}

	registry := clientregistry.New()

	var clientVersions []common.ClientVersion

	for _, version := range versions {
		cv, err := registry.CreateClientVersion(version, cas)
		if err != nil {
			return nil, fmt.Errorf("error creating client version [%s]: %w", version, err)
		}

		clientVersions = append(clientVersions, cv)
	}

	nsProvider := nsprovider.New()
	nsProvider.Add(namespace, verprovider.New(clientVersions))

	orbClient := &OrbClient{
		nsProvider: nsProvider,
		casReader:  cas,
	}

	// apply options
	for _, opt := range opts {
		opt(orbClient)
	}

	return orbClient, nil
}

// GetAnchorOrigin will retrieve anchor credential based on CID, parse Sidetree core index file referenced in anchor
// credential and return anchor origin.
func (c *OrbClient) GetAnchorOrigin(cid, suffix string) (interface{}, error) {
	anchorBytes, err := c.casReader.Read(cid)
	if err != nil {
		return nil, fmt.Errorf("unable to read CID[%s] from CAS: %w", cid, err)
	}

	logger.Debugf("read anchor[%s]: %s", cid, string(anchorBytes))

	info, err := verifiable.ParseCredential(anchorBytes, c.getParseCredentialOpts()...)
	if err != nil {
		return nil, fmt.Errorf("unable to parse verifiable credential from CID[%s] from CAS: %w", cid, err)
	}

	suffixOp, err := c.getAnchoredOperation(anchorinfo.AnchorInfo{Hashlink: cid}, info, suffix)
	if err != nil {
		return nil, fmt.Errorf("failed to get anchored operation for suffix[%s] in anchor[%s]: %w", suffix, cid, err)
	}

	if suffixOp.Type != operation.TypeCreate && suffixOp.Type != operation.TypeRecover {
		return nil, fmt.Errorf("anchor origin is only available for 'create' and 'recover' operations")
	}

	return suffixOp.AnchorOrigin, nil
}

func (c *OrbClient) getParseCredentialOpts() []verifiable.CredentialOpt {
	var opts []verifiable.CredentialOpt
	if c.publicKeyFetcher != nil {
		opts = append(opts, verifiable.WithPublicKeyFetcher(c.publicKeyFetcher))
	}

	if c.docLoader != nil {
		opts = append(opts, verifiable.WithJSONLDDocumentLoader(c.docLoader))
	}

	if c.disableProofCheck {
		opts = append(opts, verifiable.WithDisabledProofCheck())
	}

	return opts
}

func (c *OrbClient) getAnchoredOperation(anchor anchorinfo.AnchorInfo, info *verifiable.Credential, suffix string) (*operation.AnchoredOperation, error) { //nolint:lll
	anchorPayload, err := util.GetAnchorSubject(info)
	if err != nil {
		return nil, fmt.Errorf("failed to extract anchor payload from anchor[%s]: %w", anchor.Hashlink, err)
	}

	pc, err := c.nsProvider.ForNamespace(anchorPayload.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get client versions for namespace [%s]: %w", anchorPayload.Namespace, err)
	}

	v, err := pc.Get(anchorPayload.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get client version for version[%d]: %w", anchorPayload.Version, err)
	}

	ad := &util.AnchorData{OperationCount: anchorPayload.OperationCount, CoreIndexFileURI: anchorPayload.CoreIndex}

	sidetreeTxn := txnapi.SidetreeTxn{
		TransactionTime:     uint64(info.Issued.Unix()),
		AnchorString:        ad.GetAnchorString(),
		Namespace:           anchorPayload.Namespace,
		ProtocolGenesisTime: anchorPayload.Version,
		CanonicalReference:  anchor.Hashlink,
	}

	logger.Debugf("processing anchor[%s], core index[%s]", anchor.Hashlink, anchorPayload.CoreIndex)

	txnOps, err := v.OperationProvider().GetTxnOperations(&sidetreeTxn)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve operations for anchor string[%s]: %w", sidetreeTxn.AnchorString, err)
	}

	return getSuffixOp(txnOps, suffix)
}

func getSuffixOp(txnOps []*operation.AnchoredOperation, suffix string) (*operation.AnchoredOperation, error) {
	for _, op := range txnOps {
		if op.UniqueSuffix == suffix {
			return op, nil
		}
	}

	return nil, fmt.Errorf("suffix[%s] not found in anchored operations", suffix)
}
