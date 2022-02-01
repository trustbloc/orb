/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package recoverdidcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

const (
	didURIFlagName  = "did-uri"
	didURIEnvKey    = "ORB_CLI_DID_URI"
	didURIFlagUsage = "DID URI. " +
		" Alternatively, this can be set with the following environment variable: " + didURIEnvKey

	domainFlagName      = "domain"
	domainFileEnvKey    = "ORB_CLI_DOMAIN"
	domainFileFlagUsage = "URL to the did:trustbloc consortium's domain. " +
		" Alternatively, this can be set with the following environment variable: " + domainFileEnvKey

	sidetreeURLOpsFlagName  = "sidetree-url-operation"
	sidetreeURLOpsFlagUsage = "Comma-Separated list of sidetree url operation." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeURLOpsEnvKey
	sidetreeURLOpsEnvKey = "ORB_CLI_SIDETREE_URL_OPERATION"

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

	sidetreeWriteTokenFlagName  = "sidetree-write-token"
	sidetreeWriteTokenEnvKey    = "ORB_CLI_SIDETREE_WRITE_TOKEN" //nolint: gosec
	sidetreeWriteTokenFlagUsage = "The sidetree write token " +
		" Alternatively, this can be set with the following environment variable: " + sidetreeWriteTokenEnvKey

	publicKeyFileFlagName  = "publickey-file"
	publicKeyFileEnvKey    = "ORB_CLI_PUBLICKEY_FILE"
	publicKeyFileFlagUsage = "publickey file include public keys for Orb DID " +
		" Alternatively, this can be set with the following environment variable: " + publicKeyFileEnvKey

	serviceFileFlagName = "service-file"
	serviceFileEnvKey   = "ORB_CLI_SERVICE_FILE"
	serviceFlagUsage    = "publickey file include services for Orb DID " +
		" Alternatively, this can be set with the following environment variable: " + serviceFileEnvKey

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "ORB_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the recovery request." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "ORB_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the recovery request" +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "ORB_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	nextUpdateKeyFlagName  = "nextupdatekey"
	nextUpdateKeyEnvKey    = "ORB_CLI_NEXTUPDATEKEY"
	nextUpdateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyEnvKey

	nextUpdateKeyFileFlagName  = "nextupdatekey-file"
	nextUpdateKeyFileEnvKey    = "ORB_CLI_NEXTUPDATEKEY_FILE"
	nextUpdateKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyFileEnvKey

	nextRecoveryKeyFlagName  = "nextrecoverykey"
	nextRecoveryKeyEnvKey    = "ORB_CLI_NEXTRECOVERYKEY"
	nextRecoveryKeyFlagUsage = "The public key PEM used for validating the" +
		" signature of the next recovery of the document." +
		" Alternatively, this can be set with the following environment variable: " + nextRecoveryKeyEnvKey

	nextRecoveryKeyFileFlagName  = "nextrecoverkey-file"
	nextRecoveryKeyFileEnvKey    = "ORB_CLI_NEXTRECOVERYKEY_FILE"
	nextRecoveryKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for validating the signature of the next recovery of the document. " +
		" Alternatively, this can be set with the following environment variable: " + nextRecoveryKeyFileEnvKey

	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "ORB_CLI_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "did anchor origin " +
		" Alternatively, this can be set with the following environment variable: " + didAnchorOriginEnvKey
)

// GetRecoverDIDCmd returns the Cobra recover did command.
func GetRecoverDIDCmd() *cobra.Command {
	recoverDIDCmd := recoverDIDCmd()

	createFlags(recoverDIDCmd)

	return recoverDIDCmd
}

func recoverDIDCmd() *cobra.Command { //nolint: funlen
	return &cobra.Command{
		Use:          "recover",
		Short:        "Recover orb DID",
		Long:         "Recover orb DID",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			didURI, err := cmdutils.GetUserSetVarFromString(cmd, didURIFlagName,
				didURIEnvKey, false)
			if err != nil {
				return err
			}

			sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			didDoc, opts, err := recoverDIDOption(didURI, cmd)
			if err != nil {
				return err
			}

			signingKey, err := common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
				signingKeyFileEnvKey, []byte(cmdutils.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
					signingKeyPasswordEnvKey)), true)
			if err != nil {
				return err
			}

			nextUpdateKey, err := common.GetKey(cmd, nextUpdateKeyFlagName, nextUpdateKeyEnvKey, nextUpdateKeyFileFlagName,
				nextUpdateKeyFileEnvKey, nil, false)
			if err != nil {
				return err
			}

			nextRecoveryKey, err := common.GetKey(cmd, nextRecoveryKeyFlagName, nextRecoveryKeyEnvKey,
				nextRecoveryKeyFileFlagName, nextUpdateKeyFileEnvKey, nil, false)
			if err != nil {
				return err
			}

			httpClient := http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			}}

			vdr, err := orb.New(&keyRetriever{
				nextUpdateKey:   nextUpdateKey,
				signingKey:      signingKey,
				nextRecoveryKey: nextRecoveryKey,
			}, orb.WithAuthToken(sidetreeWriteToken),
				orb.WithDomain(cmdutils.GetUserSetOptionalVarFromString(cmd, domainFlagName, domainFileEnvKey)),
				orb.WithHTTPClient(&httpClient))
			if err != nil {
				return err
			}

			err = vdr.Update(didDoc, opts...)
			if err != nil {
				return fmt.Errorf("failed to recover did: %w", err)
			}

			fmt.Printf("successfully recoverd DID %s", didURI)

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	var opts []vdrapi.DIDMethodOption

	sidetreeURLOps := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLOpsFlagName,
		sidetreeURLOpsEnvKey)

	if len(sidetreeURLOps) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.OperationEndpointsOpt, sidetreeURLOps))
	}

	sidetreeURLRes := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLResFlagName,
		sidetreeURLResEnvKey)

	if len(sidetreeURLRes) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.ResolutionEndpointsOpt, sidetreeURLRes))
	}

	return opts
}

func recoverDIDOption(didID string, cmd *cobra.Command) (*ariesdid.Doc, []vdrapi.DIDMethodOption, error) {
	opts := getSidetreeURL(cmd)

	opts = append(opts, vdrapi.WithOption(orb.RecoverOpt, true))

	didDoc, err := getPublicKeys(cmd)
	if err != nil {
		return nil, nil, err
	}

	services, err := getServices(cmd)
	if err != nil {
		return nil, nil, err
	}

	didAnchorOrigin, err := cmdutils.GetUserSetVarFromString(cmd, didAnchorOriginFlagName,
		didAnchorOriginEnvKey, false)
	if err != nil {
		return nil, nil, err
	}

	opts = append(opts, vdrapi.WithOption(orb.AnchorOriginOpt, didAnchorOrigin))

	didDoc.ID = didID
	didDoc.Service = services

	return didDoc, opts, nil
}

func getServices(cmd *cobra.Command) ([]ariesdid.Service, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, serviceFileFlagName,
		serviceFileEnvKey)

	var svc []ariesdid.Service

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		for i := range services {
			svc = append(svc, services[i])
		}
	}

	return svc, nil
}

func getPublicKeys(cmd *cobra.Command) (*ariesdid.Doc, error) {
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, publicKeyFileFlagName,
		publicKeyFileEnvKey)

	if publicKeyFile != "" {
		return common.GetVDRPublicKeysFromFile(publicKeyFile)
	}

	return &ariesdid.Doc{}, nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(publicKeyFileFlagName, "", "", publicKeyFileFlagUsage)
	startCmd.Flags().StringP(serviceFileFlagName, "", "", serviceFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLOpsFlagName, "", []string{}, sidetreeURLOpsFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLResFlagName, "", []string{}, sidetreeURLResFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFlagName, "", "", nextUpdateKeyFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFileFlagName, "", "", nextUpdateKeyFileFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
	startCmd.Flags().StringP(nextRecoveryKeyFlagName, "", "", nextRecoveryKeyFlagUsage)
	startCmd.Flags().StringP(nextRecoveryKeyFileFlagName, "", "", nextRecoveryKeyFileFlagUsage)
	startCmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
}

type keyRetriever struct {
	nextUpdateKey   crypto.PublicKey
	nextRecoveryKey crypto.PublicKey
	signingKey      crypto.PublicKey
}

func (k *keyRetriever) GetNextRecoveryPublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return k.nextRecoveryKey, nil
}

func (k *keyRetriever) GetNextUpdatePublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return k.nextUpdateKey, nil
}

func (k *keyRetriever) GetSigningKey(didID string, ot orb.OperationType, commitment string) (crypto.PrivateKey, error) {
	return k.signingKey, nil
}
