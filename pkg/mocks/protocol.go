/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"fmt"
	"sync"

	"github.com/trustbloc/sidetree-core-go/pkg/api/cas"
	"github.com/trustbloc/sidetree-core-go/pkg/api/protocol"
	"github.com/trustbloc/sidetree-core-go/pkg/compression"
	"github.com/trustbloc/sidetree-core-go/pkg/mocks"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doccomposer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/doctransformer/didtransformer"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/docvalidator/didvalidator"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationapplier"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/1_0/txnprovider"

	"github.com/trustbloc/orb/pkg/context/common"
	orboperationparser "github.com/trustbloc/orb/pkg/versions/1_0/operationparser"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchororigin"
	"github.com/trustbloc/orb/pkg/versions/1_0/operationparser/validators/anchortime"
	"github.com/trustbloc/orb/pkg/versions/1_0/txnprocessor"
)

// DefaultNS is default namespace used in mocks.
const DefaultNS = "did:sidetree"

// maximum batch files size in bytes.
const maxBatchFileSize = 20000

// MockProtocolClient mocks protocol for testing purposes.
type MockProtocolClient struct {
	currentVersion *mocks.ProtocolVersion
	versions       []*mocks.ProtocolVersion
}

// Current mocks getting last protocol version.
func (m *MockProtocolClient) Current() (protocol.Version, error) {
	return m.currentVersion, nil
}

// Get mocks getting protocol version based on blockchain(transaction) time.
func (m *MockProtocolClient) Get(transactionTime uint64) (protocol.Version, error) {
	for i := len(m.versions) - 1; i >= 0; i-- {
		if transactionTime >= m.versions[i].Protocol().GenesisTime {
			return m.versions[i], nil
		}
	}

	return nil, fmt.Errorf("protocol parameters are not defined for blockchain time: %d", transactionTime)
}

// NewMockProtocolClientProvider creates new mock protocol client provider.
func NewMockProtocolClientProvider() *MockProtocolClientProvider {
	opStore := NewMockOperationStore()
	casClient := mocks.NewMockCasClient(nil)

	return &MockProtocolClientProvider{
		clients:       make(map[string]protocol.Client),
		opStore:       opStore,
		opStoreClient: opStore,
		casClient:     casClient,
	}
}

// MockProtocolClientProvider implements mock protocol client provider.
type MockProtocolClientProvider struct {
	mutex          sync.Mutex
	clients        map[string]protocol.Client
	opStoreClient  processor.OperationStoreClient
	opStore        common.OperationStore
	casClient      cas.Client
	anchorGraph    common.AnchorGraph
	methodCtx      []string
	baseEnabled    bool
	allowedOrigins []string
}

// WithOpStoreClient sets the operation store client.
func (m *MockProtocolClientProvider) WithOpStoreClient(opStoreClient processor.OperationStoreClient) *MockProtocolClientProvider { //nolint:lll
	m.opStoreClient = opStoreClient

	return m
}

// WithOpStore sets the operation store.
func (m *MockProtocolClientProvider) WithOpStore(opStore common.OperationStore) *MockProtocolClientProvider {
	m.opStore = opStore

	return m
}

// WithCasClient sets the CAS client.
func (m *MockProtocolClientProvider) WithCasClient(casClient cas.Client) *MockProtocolClientProvider {
	m.casClient = casClient

	return m
}

// WithAnchorGraph sets the anchor graph.
func (m *MockProtocolClientProvider) WithAnchorGraph(anchorGraph common.AnchorGraph) *MockProtocolClientProvider {
	m.anchorGraph = anchorGraph

	return m
}

// WithMethodContext sets method context for document transformer.
func (m *MockProtocolClientProvider) WithMethodContext(ctx []string) *MockProtocolClientProvider {
	m.methodCtx = ctx

	return m
}

// WithBase enables @base property during document transformation.
func (m *MockProtocolClientProvider) WithBase(enabled bool) *MockProtocolClientProvider {
	m.baseEnabled = enabled

	return m
}

// WithAllowedOrigins allows for specifying allowed origins.
func (m *MockProtocolClientProvider) WithAllowedOrigins(origins []string) *MockProtocolClientProvider {
	m.allowedOrigins = origins

	return m
}

// ForNamespace will return protocol client for that namespace.
func (m *MockProtocolClientProvider) ForNamespace(namespace string) (protocol.Client, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	pc, ok := m.clients[namespace]
	if !ok {
		pc = m.create()
		m.clients[namespace] = pc
	}

	return pc, nil
}

func (m *MockProtocolClientProvider) create() *MockProtocolClient {
	//nolint:gomnd
	latest := protocol.Protocol{
		GenesisTime:                  0,
		MultihashAlgorithms:          []uint{18},
		MaxOperationCount:            1,    // one operation per batch - batch gets cut right away
		MaxOperationSize:             2500, // has to be bigger than max delta + max proof + small number for type
		MaxOperationHashLength:       100,
		MaxDeltaSize:                 1700, // our test is about 1100 since we have multiple public keys/services
		MaxCasURILength:              100,
		CompressionAlgorithm:         "GZIP",
		MaxChunkFileSize:             maxBatchFileSize,
		MaxProvisionalIndexFileSize:  maxBatchFileSize,
		MaxCoreIndexFileSize:         maxBatchFileSize,
		MaxProofFileSize:             maxBatchFileSize,
		Patches:                      []string{"replace", "add-public-keys", "remove-public-keys", "add-services", "remove-services", "ietf-json-patch"}, //nolint:lll
		SignatureAlgorithms:          []string{"EdDSA", "ES256", "ES256K"},
		KeyAlgorithms:                []string{"Ed25519", "P-256", "secp256k1"},
		MaxMemoryDecompressionFactor: 3,
	}

	parser := operationparser.New(latest,
		operationparser.WithAnchorTimeValidator(anchortime.New(latest.MaxOperationTimeDelta)),
		operationparser.WithAnchorOriginValidator(anchororigin.New(m.allowedOrigins)))

	orbParser := orboperationparser.New(parser)

	cp := compression.New(compression.WithDefaultAlgorithms())
	op := txnprovider.NewOperationProvider(latest, parser, m.casClient, cp)
	th := txnprovider.NewOperationHandler(latest, m.casClient, cp, parser)
	dc := doccomposer.New()
	oa := operationapplier.New(latest, parser, dc)

	dv := didvalidator.New(m.opStoreClient)
	dt := didtransformer.New(didtransformer.WithMethodContext(m.methodCtx), didtransformer.WithBase(m.baseEnabled))

	txnProcessor := txnprocessor.New(
		&txnprocessor.Providers{
			OpStore:                   m.opStore,
			OperationProtocolProvider: op,
		},
	)

	pv := &mocks.ProtocolVersion{}
	pv.OperationApplierReturns(oa)
	pv.OperationParserReturns(orbParser)
	pv.DocumentComposerReturns(dc)
	pv.DocumentValidatorReturns(dv)
	pv.DocumentTransformerReturns(dt)
	pv.OperationProviderReturns(op)
	pv.OperationHandlerReturns(th)
	pv.TransactionProcessorReturns(txnProcessor)

	pv.ProtocolReturns(latest)

	return &MockProtocolClient{
		currentVersion: pv,
		versions:       []*mocks.ProtocolVersion{pv},
	}
}
