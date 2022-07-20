/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aoprovider

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/api/operation"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	txnapi "github.com/trustbloc/sidetree-core-go/pkg/api/txn"

	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset"
	"github.com/trustbloc/orb/pkg/anchor/anchorlinkset/generator"
	anchorinfo "github.com/trustbloc/orb/pkg/anchor/info"
	"github.com/trustbloc/orb/pkg/anchor/subject"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/config"
	"github.com/trustbloc/orb/pkg/context/common"
	"github.com/trustbloc/orb/pkg/linkset"
	"github.com/trustbloc/orb/pkg/orbclient/protocol/nsprovider"
	"github.com/trustbloc/orb/pkg/orbclient/protocol/verprovider"
	"github.com/trustbloc/orb/pkg/protocolversion/clientregistry"
)

var logger = log.New("orb-client")

const v1 = "1.0"

// OrbClient implements Orb client.
type OrbClient struct {
	nsProvider     namespaceProvider
	versions       []string
	currentVersion string

	publicKeyFetcher     verifiable.PublicKeyFetcher
	docLoader            ld.DocumentLoader
	casReader            common.CASReader
	anchorLinksetBuilder anchorLinksetBuilder
	disableProofCheck    bool
}

type namespaceProvider interface {
	ForNamespace(namespace string) (nsprovider.ClientVersionProvider, error)
}

type anchorLinksetBuilder interface {
	GetPayloadFromAnchorLink(anchorLink *linkset.Link) (*subject.Payload, error)
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

// WithProtocolVersions sets optional client protocol versions.
func WithProtocolVersions(versions []string) Option {
	return func(opts *OrbClient) {
		opts.versions = versions
	}
}

// WithCurrentProtocolVersion sets optional current protocol versions.
// Defaults to the latest in the protocol versions list.
func WithCurrentProtocolVersion(version string) Option {
	return func(opts *OrbClient) {
		opts.currentVersion = version
	}
}

// New creates new Orb client.
func New(namespace string, cas common.CASReader, opts ...Option) (*OrbClient, error) {
	orbClient := &OrbClient{
		casReader:            cas,
		versions:             []string{v1},
		anchorLinksetBuilder: anchorlinkset.NewBuilder(generator.NewRegistry()),
	}

	// apply options
	for _, opt := range opts {
		opt(orbClient)
	}

	registry := clientregistry.New()

	var clientVersions []protocol.Version

	for _, version := range orbClient.versions {
		cv, err := registry.CreateClientVersion(version, cas, &config.Sidetree{})
		if err != nil {
			return nil, fmt.Errorf("error creating client version [%s]: %w", version, err)
		}

		clientVersions = append(clientVersions, cv)
	}

	verProvider, err := verprovider.New(clientVersions, verprovider.WithCurrentProtocolVersion(orbClient.currentVersion))
	if err != nil {
		return nil, err
	}

	nsProvider := nsprovider.New()
	nsProvider.Add(namespace, verProvider)

	orbClient.nsProvider = nsProvider

	return orbClient, nil
}

// GetAnchorOrigin will retrieve anchor credential based on CID, parse Sidetree core index file referenced in anchor
// credential and return anchor origin.
func (c *OrbClient) GetAnchorOrigin(cid, suffix string) (interface{}, error) {
	anchorLinksetBytes, err := c.casReader.Read(cid)
	if err != nil {
		return nil, fmt.Errorf("unable to read anchor[%s] from CAS: %w", cid, err)
	}

	logger.Debugf("read anchor[%s]: %s", cid, string(anchorLinksetBytes))

	anchorLinkset := &linkset.Linkset{}

	err = json.Unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor from CID[%s] from CAS: %w", cid, err)
	}

	anchorLink := anchorLinkset.Link()
	if anchorLink == nil {
		return nil, fmt.Errorf("empty anchor Linkset [%s]", cid)
	}

	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLink, c.getParseCredentialOpts()...)
	if err != nil {
		return nil, fmt.Errorf("get verifiable credential from anchor for CID[%s]: %w", cid, err)
	}

	suffixOp, err := c.getAnchoredOperation(anchorinfo.AnchorInfo{Hashlink: cid}, anchorLink, vc, suffix)
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

func (c *OrbClient) getAnchoredOperation(anchor anchorinfo.AnchorInfo, anchorLink *linkset.Link, vc *verifiable.Credential, suffix string) (*operation.AnchoredOperation, error) { //nolint:lll
	anchorPayload, err := c.anchorLinksetBuilder.GetPayloadFromAnchorLink(anchorLink)
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
		TransactionTime:    uint64(vc.Issued.Unix()),
		AnchorString:       ad.GetAnchorString(),
		Namespace:          anchorPayload.Namespace,
		ProtocolVersion:    anchorPayload.Version,
		CanonicalReference: anchor.Hashlink,
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
