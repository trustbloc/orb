/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	restcommon "github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

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

	sidetreeTokenFlagName  = "sidetree-write-token"
	sidetreeTokenEnvKey    = "ORB_DRIVER_SIDETREE_TOKEN" //nolint: gosec
	sidetreeTokenFlagUsage = "The sidetree token." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeTokenEnvKey
)

var logger = log.New("orb-driver")

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// Start starts the http server.
func (s *HTTPServer) Start(srv *httpserver.Server) error {
	if err := srv.Start(); err != nil {
		return err
	}

	logger.Infof("started orb driver service")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Wait for interrupt
	<-interrupt

	return nil
}

type parameters struct {
	hostURL           string
	tlsSystemCertPool bool
	tlsCACerts        []string
	discoveryDomain   string
	sidetreeToken     string
	tlsCertificate    string
	tlsKey            string
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
	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	tlsCertificate := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsCertificateFlagName, tlsCertificateLEnvKey)

	tlsKey := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsKeyFlagName, tlsKeyEnvKey)

	sidetreeToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeTokenFlagName,
		sidetreeTokenEnvKey)

	discoveryDomain, err := cmdutils.GetUserSetVarFromString(cmd, domainFlagName, domainEnvKey,
		false)
	if err != nil {
		return nil, err
	}

	return &parameters{
		hostURL:           hostURL,
		tlsSystemCertPool: tlsSystemCertPool,
		tlsCACerts:        tlsCACerts,
		discoveryDomain:   discoveryDomain,
		sidetreeToken:     sidetreeToken,
		tlsCertificate:    tlsCertificate,
		tlsKey:            tlsKey,
	}, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
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
}

func startDriver(parameters *parameters) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	orbVDR, err := orb.New(nil, orb.WithAuthToken(parameters.sidetreeToken),
		orb.WithDomain(parameters.discoveryDomain),
		orb.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))
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
		handlers...,
	)

	srv := &HTTPServer{}

	return srv.Start(httpServer)
}
