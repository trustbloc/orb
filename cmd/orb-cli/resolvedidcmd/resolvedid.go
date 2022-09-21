/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package resolvedidcmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/internal/pkg/tlsutil"
)

const (
	didURIFlagName  = "did-uri"
	didURIEnvKey    = "ORB_CLI_DID_URI"
	didURIFlagUsage = "DID URI. " +
		" Alternatively, this can be set with the following environment variable: " + didURIEnvKey

	domainFlagName      = "domain"
	domainFileEnvKey    = "ORB_CLI_DOMAIN"
	domainFileFlagUsage = "URL to the did:orb domain. " +
		" Alternatively, this can be set with the following environment variable: " + domainFileEnvKey

	sidetreeURLResFlagName  = "sidetree-url-resolution"
	sidetreeURLResFlagUsage = "Comma-Separated list of sidetree url resolution." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeURLResEnvKey
	sidetreeURLResEnvKey = "ORB_CLI_SIDETREE_URL_Resolution"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ORB_CLI_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ORB_CLI_TLS_CACERTS"

	authTokenFlagName  = "auth-token"
	authTokenEnvKey    = "ORB_CLI_AUTH_TOKEN" //nolint: gosec
	authTokenFlagUsage = "The auth token." +
		" Alternatively, this can be set with the following environment variable: " + authTokenEnvKey

	verifyTypeFlagName  = "verify-resolution-result-type"
	verifyTypeEnvKey    = "ORB_CLI_VERIFY_RESOLUTION_RESULT_TYPE"
	verifyTypeFlagUsage = "verify resolution result type. Values [all, none, unpublished] " +
		" Alternatively, this can be set with the following environment variable: " + verifyTypeEnvKey
)

const (
	verifyTypeAll         = "all"
	verifyTypeUnpublished = "unpublished"
	verifyTypeNone        = "none"
)

// GetResolveDIDCmd returns the Cobra resolve did command.
func GetResolveDIDCmd() *cobra.Command {
	resolveDIDCmd := resolveDIDCmd()

	createFlags(resolveDIDCmd)

	return resolveDIDCmd
}

func resolveDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "resolve",
		Short:        "Resolve orb DID",
		Long:         "Resolve orb DID",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			didURI, err := cmdutil.GetUserSetVarFromString(cmd, didURIFlagName,
				didURIEnvKey, false)
			if err != nil {
				return err
			}

			authToken := cmdutil.GetUserSetOptionalVarFromString(cmd, authTokenFlagName,
				authTokenEnvKey)

			domain := cmdutil.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			verifyResolutionResultType, err := getVerifyResolutionResultType(cmd)
			if err != nil {
				return err
			}

			httpClient := http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			}}

			vdr, err := orb.New(nil,
				orb.WithAuthToken(authToken), orb.WithDomain(domain),
				orb.WithVerifyResolutionResultType(verifyResolutionResultType),
				orb.WithHTTPClient(&httpClient))
			if err != nil {
				return err
			}

			didDoc, err := vdr.Read(didURI, resolveDIDOption(cmd)...)
			if err != nil {
				return fmt.Errorf("failed to resolve did: %w", err)
			}

			docBytes, err := didDoc.JSONBytes()
			if err != nil {
				return err
			}

			fmt.Printf("%s", docBytes)

			return nil
		},
	}
}

func resolveDIDOption(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	return getSidetreeURL(cmd)
}

func getSidetreeURL(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	var opts []vdrapi.DIDMethodOption

	sidetreeURLRes := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLResFlagName,
		sidetreeURLResEnvKey)

	if len(sidetreeURLRes) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.ResolutionEndpointsOpt, sidetreeURLRes))
	}

	return opts
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

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutil.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsutil.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(authTokenFlagName, "", "", authTokenFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLResFlagName, "", []string{}, sidetreeURLResFlagUsage)
	startCmd.Flags().StringP(verifyTypeFlagName, "", "", verifyTypeFlagUsage)
}
