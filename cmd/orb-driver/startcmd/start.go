/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/spf13/cobra"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/internal/pkg/tlsutil"
	driverrest "github.com/trustbloc/orb/pkg/driver/restapi"
	"github.com/trustbloc/orb/pkg/httpserver"
)

const (
	hostURLFlagName  = "host-url"
	hostURLFlagUsage = "URL to run the orb driver instance on. Format: HostName:Port."
	hostURLEnvKey    = "ORB_DRIVER_HOST_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ORB_DRIVER_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ORB_DRIVER_TLS_CACERTS"

	tlsCertificateFlagName  = "tls-certificate"
	tlsCertificateFlagUsage = "TLS certificate for ORB server. " +
		" Alternatively, this can be set with the following environment variable: " + tlsCertificateLEnvKey
	tlsCertificateLEnvKey = "ORB_DRIVER_TLS_CERTIFICATE"

	tlsKeyFlagName  = "tls-key"
	tlsKeyFlagUsage = "TLS key for ORB server. " +
		" Alternatively, this can be set with the following environment variable: " + tlsKeyEnvKey
	tlsKeyEnvKey = "ORB_DRIVER_TLS_KEY"

	domainFlagName  = "domain"
	domainFlagUsage = "discovery endpoint domain"
	domainEnvKey    = "ORB_DRIVER_DOMAIN"

	verifyTypeFlagName  = "verify-resolution-result-type"
	verifyTypeEnvKey    = "ORB_DRIVER_VERIFY_RESOLUTION_RESULT_TYPE"
	verifyTypeFlagUsage = "verify resolution result type. Values [all, none, unpublished] " +
		" Alternatively, this can be set with the following environment variable: " + verifyTypeEnvKey

	sidetreeTokenFlagName  = "sidetree-write-token"
	sidetreeTokenEnvKey    = "ORB_DRIVER_SIDETREE_TOKEN" //nolint: gosec
	sidetreeTokenFlagUsage = "The sidetree token." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeTokenEnvKey
)

const (
	verifyTypeAll         = "all"
	verifyTypeUnpublished = "unpublished"
	verifyTypeNone        = "none"
)

var logger = log.New("orb-driver")

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// Start starts the http server.
func (s *HTTPServer) Start(srv *httpserver.Server) error {
	if err := srv.Start(); err != nil {
		return err
	}

	logger.Info("started orb driver service")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	return nil
}

type parameters struct {
	hostURL                    string
	tlsSystemCertPool          bool
	tlsCACerts                 []string
	discoveryDomain            string
	sidetreeToken              string
	tlsCertificate             string
	tlsKey                     string
	verifyResolutionResultType orb.VerifyResolutionResultType
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd() *cobra.Command {
	startCmd := createStartCmd()

	createFlags(startCmd)

	return startCmd
}

func createStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start orb driver",
		Long:  "Start orb driver",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters(cmd)
			if err != nil {
				return err
			}

			return startDriver(parameters)
		},
	}
}

func getParameters(cmd *cobra.Command) (*parameters, error) {
	hostURL, err := cmdutil.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	tlsCertificate := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsCertificateFlagName, tlsCertificateLEnvKey)

	tlsKey := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsKeyFlagName, tlsKeyEnvKey)

	sidetreeToken := cmdutil.GetUserSetOptionalVarFromString(cmd, sidetreeTokenFlagName,
		sidetreeTokenEnvKey)

	discoveryDomain := cmdutil.GetUserSetOptionalVarFromString(cmd, domainFlagName, domainEnvKey)

	verifyResolutionResultType, err := getVerifyResolutionResultType(cmd)
	if err != nil {
		return nil, err
	}

	return &parameters{
		hostURL:                    hostURL,
		tlsSystemCertPool:          tlsSystemCertPool,
		tlsCACerts:                 tlsCACerts,
		discoveryDomain:            discoveryDomain,
		sidetreeToken:              sidetreeToken,
		tlsCertificate:             tlsCertificate,
		tlsKey:                     tlsKey,
		verifyResolutionResultType: verifyResolutionResultType,
	}, nil
}

func getVerifyResolutionResultType(cmd *cobra.Command) (orb.VerifyResolutionResultType, error) {
	verifyTypeString, err := cmdutil.GetUserSetVarFromString(cmd, verifyTypeFlagName,
		verifyTypeEnvKey, false)
	if err != nil {
		return -1, err
	}

	switch strings.ToLower(verifyTypeString) {
	case verifyTypeNone:
		return orb.None, nil
	case verifyTypeAll:
		return orb.All, nil
	case verifyTypeUnpublished:
		return orb.Unpublished, nil
	}

	return -1, fmt.Errorf("unsupported %s for verifyResolutionResultType", verifyTypeString)
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsSystemCertPool, tlsCACerts, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, "", "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFlagUsage)
	startCmd.Flags().StringP(sidetreeTokenFlagName, "", "", sidetreeTokenFlagUsage)
	startCmd.Flags().StringP(tlsCertificateFlagName, "", "", tlsCertificateFlagUsage)
	startCmd.Flags().StringP(tlsKeyFlagName, "", "", tlsKeyFlagUsage)
	startCmd.Flags().StringP(verifyTypeFlagName, "", "", verifyTypeFlagUsage)
}

func startDriver(parameters *parameters) error {
	rootCAs, err := tlsutil.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	opts := make([]orb.Option, 0)

	opts = append(opts, orb.WithAuthToken(parameters.sidetreeToken),
		orb.WithVerifyResolutionResultType(parameters.verifyResolutionResultType),
		orb.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))

	if parameters.discoveryDomain != "" {
		opts = append(opts, orb.WithDomain(parameters.discoveryDomain))
	}

	orbVDR, err := orb.New(nil, opts...)
	if err != nil {
		return err
	}

	// create driver rest api
	endpointDiscoveryOp := driverrest.New(&driverrest.Config{
		OrbVDR: orbVDR,
	})

	handlers := make([]restcommon.HTTPHandler, 0)

	handlers = append(handlers,
		endpointDiscoveryOp.GetRESTHandlers()...)

	httpServer := httpserver.New(
		parameters.hostURL,
		parameters.tlsCertificate,
		parameters.tlsKey,
		20*time.Second, //nolint: gomnd
		20*time.Second, //nolint: gomnd
		nil,
		nil,
		nil,
		nil,
		handlers...,
	)

	srv := &HTTPServer{}

	return srv.Start(httpServer)
}
