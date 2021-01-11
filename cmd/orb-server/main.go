/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/trustbloc/sidetree-core-go/pkg/api/txn"
	"github.com/trustbloc/sidetree-core-go/pkg/batch"
	"github.com/trustbloc/sidetree-core-go/pkg/dochandler"
	"github.com/trustbloc/sidetree-core-go/pkg/observer"
	"github.com/trustbloc/sidetree-core-go/pkg/processor"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/diddochandler"
	"github.com/trustbloc/sidetree-mock/pkg/mocks"

	sidetreecontext "github.com/trustbloc/orb/pkg/context"
	"github.com/trustbloc/orb/pkg/context/blockchain"
	"github.com/trustbloc/orb/pkg/context/cas"
	"github.com/trustbloc/orb/pkg/httpserver"
	"github.com/trustbloc/orb/pkg/txnlog/memlog"
)

var logger = logrus.New()

var config = viper.New()

const (
	defaultDIDDocNamespace = "did:orb"
	basePath               = "/sidetree/0.0.1"
	arrayDelimiter         = ","
	txnBuffer              = 100
)

func main() { // nolint:funlen
	config.SetEnvPrefix("SIDETREE_IPFS")
	config.AutomaticEnv()
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	logger.Info("starting sidetree ipfs node...")

	didDocNamespace := defaultDIDDocNamespace
	if config.GetString("did.namespace") != "" {
		didDocNamespace = config.GetString("did.namespace")
	}

	var aliases []string
	if config.GetString("did.aliases") != "" {
		aliases = strings.Split(config.GetString("did.aliases"), arrayDelimiter)
	}

	var methodCtx []string
	if config.GetString("did.method.context") != "" {
		methodCtx = strings.Split(config.GetString("did.method.context"), arrayDelimiter)
	}

	baseEnabled := false
	if config.GetString("did.base.enabled") != "" {
		baseEnabled = config.GetBool("did.base.enabled")
	}

	if config.GetString("cas.url") == "" {
		logger.Error("You must specify CAS URL")
		panic("You must specify CAS URL")
	}

	casClient := cas.New(config.GetString("cas.url"))

	logger.Info("starting sidetree node...")

	opStore := mocks.NewMockOperationStore()

	pcp := mocks.NewMockProtocolClientProvider().WithOpStore(opStore).WithOpStoreClient(opStore).WithMethodContext(methodCtx).WithBase(baseEnabled).WithCasClient(casClient) //nolint: lll

	pc, err := pcp.ForNamespace(mocks.DefaultNS)
	if err != nil {
		logger.Errorf("Failed to get protocol client for namespace [%s]: %s", mocks.DefaultNS, err.Error())
		panic(err)
	}

	sidetreeTxnCh := make(chan []txn.SidetreeTxn, txnBuffer)

	bc := blockchain.New("did:sidetree", memlog.New(), sidetreeTxnCh)

	ctx := sidetreecontext.New(pc, bc)

	// create new batch writer
	batchWriter, err := batch.New(didDocNamespace, ctx)
	if err != nil {
		logger.Errorf("Failed to create batch writer: %s", err.Error())
		panic(err)
	}

	// start routine for creating batches
	batchWriter.Start()

	logger.Info("started batch writer")

	providers := &observer.Providers{
		Ledger:                 mockLedger{registerForSidetreeTxnValue: sidetreeTxnCh},
		ProtocolClientProvider: pcp,
	}

	observer.New(providers).Start()

	logger.Info("started observer")

	// did document handler with did document validator for didDocNamespace
	didDocHandler := dochandler.New(
		didDocNamespace,
		aliases,
		pc,
		batchWriter,
		processor.New(didDocNamespace, opStore, pc),
	)

	restSvc := httpserver.New(
		getListenURL(),
		config.GetString("tls.certificate"),
		config.GetString("tls.key"),
		config.GetString("api.token"),
		diddochandler.NewUpdateHandler(basePath, didDocHandler, pc),
		diddochandler.NewResolveHandler(basePath, didDocHandler),
	)

	if restSvc.Start() != nil {
		panic(err)
	}

	logger.Info("started rest service")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	// Shut down all services
	batchWriter.Stop()

	if err := restSvc.Stop(context.Background()); err != nil {
		logger.Errorf("Error stopping REST service: %s", err)
	}
}

func getListenURL() string {
	host := config.GetString("host")
	if host == "" {
		host = "0.0.0.0"
	}

	port := config.GetInt("port")
	if port == 0 {
		panic("port is not set")
	}

	return fmt.Sprintf("%s:%d", host, port)
}

type mockLedger struct {
	registerForSidetreeTxnValue chan []txn.SidetreeTxn
}

func (m mockLedger) RegisterForSidetreeTxn() <-chan []txn.SidetreeTxn {
	return m.registerForSidetreeTxnValue
}
