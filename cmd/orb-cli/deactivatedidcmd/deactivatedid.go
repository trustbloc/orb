/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package deactivatedidcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree/api"
	webcrypto "github.com/hyperledger/aries-framework-go/pkg/crypto"
	webkmscrypto "github.com/hyperledger/aries-framework-go/pkg/crypto/webkms"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/spf13/cobra"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
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

	kmsStoreEndpointFlagName  = "kms-store-endpoint"
	kmsStoreEndpointFlagUsage = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsStoreEndpointEnvKey
	kmsStoreEndpointEnvKey = "ORB_CLI_KMS_STORE_ENDPOINT"

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

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "ORB_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the deactivate request." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "ORB_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the deactivate request" +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "ORB_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	signingKeyIDFlagName  = "signingkey-id"
	signingKeyIDEnvKey    = "ORB_CLI_SIGNINGKEY_ID"
	signingKeyIDFlagUsage = "The key id in kms" +
		" used for signing the deactivate of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyIDEnvKey
)

// GetDeactivateDIDCmd returns the Cobra deactivate did command.
func GetDeactivateDIDCmd() *cobra.Command {
	deactivateDIDCmd := deactivateDIDCmd()

	createFlags(deactivateDIDCmd)

	return deactivateDIDCmd
}

func deactivateDIDCmd() *cobra.Command { //nolint:funlen
	return &cobra.Command{
		Use:          "deactivate",
		Short:        "Deactivate orb DID",
		Long:         "Deactivate orb DID",
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

			sidetreeWriteToken := cmdutil.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			domain := cmdutil.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			httpClient := http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			}}

			kmsStoreURL := cmdutil.GetUserSetOptionalVarFromString(cmd, kmsStoreEndpointFlagName,
				kmsStoreEndpointEnvKey)

			var webKmsClient kms.KeyManager
			var webKmsCryptoClient webcrypto.Crypto

			if kmsStoreURL != "" {
				webKmsClient = webkms.New(kmsStoreURL, &httpClient)
				webKmsCryptoClient = webkmscrypto.New(kmsStoreURL, &httpClient)
			}

			var signingKey interface{}
			var signingKeyID string
			var signingKeyPK interface{}

			if webKmsClient == nil {
				signingKey, err = common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
					signingKeyFileEnvKey, []byte(cmdutil.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
						signingKeyPasswordEnvKey)), true)
				if err != nil {
					return err
				}
			} else {
				signingKeyID, err = cmdutil.GetUserSetVarFromString(cmd, signingKeyIDFlagName,
					signingKeyIDEnvKey, false)
				if err != nil {
					return err
				}

				signingKeyID = fmt.Sprintf("%s/keys/%s", kmsStoreURL, signingKeyID)

				signingKeyPK, err = common.GetPublicKeyFromKMS(cmd, signingKeyIDFlagName,
					signingKeyIDEnvKey, webKmsClient)
				if err != nil {
					return err
				}
			}

			vdr, err := orb.New(&keyRetriever{
				signingKey:         signingKey,
				signingKeyID:       signingKeyID,
				webKmsCryptoClient: webKmsCryptoClient,
				signingKeyPK:       signingKeyPK,
			},
				orb.WithAuthToken(sidetreeWriteToken), orb.WithDomain(domain),
				orb.WithHTTPClient(&httpClient))
			if err != nil {
				return err
			}

			err = vdr.Deactivate(didURI, deactivateDIDOption(cmd)...)
			if err != nil {
				return fmt.Errorf("failed to deactivate did: %w", err)
			}

			fmt.Printf("successfully deactivated DID %s", didURI)

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	var opts []vdrapi.DIDMethodOption

	sidetreeURLOps := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLOpsFlagName,
		sidetreeURLOpsEnvKey)

	if len(sidetreeURLOps) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.OperationEndpointsOpt, sidetreeURLOps))
	}

	sidetreeURLRes := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLResFlagName,
		sidetreeURLResEnvKey)

	if len(sidetreeURLRes) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.ResolutionEndpointsOpt, sidetreeURLRes))
	}

	return opts
}

func deactivateDIDOption(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	return getSidetreeURL(cmd)
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

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLOpsFlagName, "", []string{}, sidetreeURLOpsFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLResFlagName, "", []string{}, sidetreeURLResFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
	startCmd.Flags().String(kmsStoreEndpointFlagName, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().String(signingKeyIDFlagName, "", signingKeyIDFlagUsage)
}

type keyRetriever struct {
	signingKey         crypto.PublicKey
	signingKeyID       string
	webKmsCryptoClient webcrypto.Crypto
	signingKeyPK       crypto.PublicKey
}

func (k *keyRetriever) GetNextRecoveryPublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetNextUpdatePublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetSigner(didID string, ot orb.OperationType, commitment string) (api.Signer, error) {
	return common.NewSigner(k.signingKey, k.signingKeyID, k.webKmsCryptoClient, k.signingKeyPK), nil
}
