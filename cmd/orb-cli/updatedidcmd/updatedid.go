/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updatedidcmd

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
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
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

	addPublicKeyFileFlagName  = "add-publickey-file"
	addPublicKeyFileEnvKey    = "ORB_CLI_ADD_PUBLICKEY_FILE"
	addPublicKeyFileFlagUsage = "publickey file include public keys to be added for Orb DID " +
		" Alternatively, this can be set with the following environment variable: " + addPublicKeyFileEnvKey

	addServiceFileFlagName = "add-service-file"
	addServiceFileEnvKey   = "ORB_CLI_ADD_SERVICE_FILE"
	addServiceFlagUsage    = "publickey file include services to be added for Orb DID " +
		" Alternatively, this can be set with the following environment variable: " + addServiceFileEnvKey

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "ORB_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the update of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "ORB_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the update of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "ORB_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	signingKeyIDFlagName  = "signingkey-id"
	signingKeyIDEnvKey    = "ORB_CLI_SIGNINGKEY_ID"
	signingKeyIDFlagUsage = "The key id in kms" +
		" used for signing the update of the document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyIDEnvKey

	nextUpdateKeyFlagName  = "nextupdatekey"
	nextUpdateKeyEnvKey    = "ORB_CLI_NEXTUPDATEKEY"
	nextUpdateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyEnvKey

	nextUpdateKeyFileFlagName  = "nextupdatekey-file"
	nextUpdateKeyFileEnvKey    = "ORB_CLI_NEXTUPDATEKEY_FILE"
	nextUpdateKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyFileEnvKey

	nextUpdateKeyIDFlagName  = "nextupdatekey-id"
	nextUpdateKeyIDEnvKey    = "ORB_CLI_NEXTUPDATEKEY_ID"
	nextUpdateKeyIDFlagUsage = "The key id in kms" +
		" used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyIDEnvKey
)

// GetUpdateDIDCmd returns the Cobra update did command.
func GetUpdateDIDCmd() *cobra.Command {
	updateDIDCmd := updateDIDCmd()

	createFlags(updateDIDCmd)

	return updateDIDCmd
}

func updateDIDCmd() *cobra.Command { //nolint: funlen,gocyclo,cyclop
	return &cobra.Command{
		Use:          "update",
		Short:        "Update Orb DID",
		Long:         "Update Orb DID",
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

			domain := cmdutils.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			didDoc, opts, err := updateDIDOption(didURI, cmd)
			if err != nil {
				return err
			}

			httpClient := http.Client{Transport: &http.Transport{
				ForceAttemptHTTP2: true,
				TLSClientConfig:   &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
			}}

			kmsStoreURL := cmdutils.GetUserSetOptionalVarFromString(cmd, kmsStoreEndpointFlagName,
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
			var nextUpdateKey interface{}

			if webKmsClient == nil { //nolint: nestif
				signingKey, err = common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
					signingKeyFileEnvKey, []byte(cmdutils.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
						signingKeyPasswordEnvKey)), true)
				if err != nil {
					return err
				}

				nextUpdateKey, err = common.GetKey(cmd, nextUpdateKeyFlagName, nextUpdateKeyEnvKey, nextUpdateKeyFileFlagName,
					nextUpdateKeyFileEnvKey, nil, false)
				if err != nil {
					return err
				}
			} else {
				nextUpdateKey, err = common.GetPublicKeyFromKMS(cmd, nextUpdateKeyIDFlagName, nextUpdateKeyIDEnvKey, webKmsClient)
				if err != nil {
					return err
				}

				signingKeyID, err = cmdutils.GetUserSetVarFromString(cmd, signingKeyIDFlagName,
					signingKeyIDEnvKey, false)
				if err != nil {
					return err
				}

				signingKeyPK, err = common.GetPublicKeyFromKMS(cmd, signingKeyIDFlagName,
					signingKeyIDEnvKey, webKmsClient)
				if err != nil {
					return err
				}
			}

			vdr, err := orb.New(&keyRetriever{
				nextUpdateKey:      nextUpdateKey,
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

			err = vdr.Update(didDoc, opts...)
			if err != nil {
				return fmt.Errorf("failed to update did: %w", err)
			}

			fmt.Printf("successfully updated DID %s", didURI)

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

func updateDIDOption(didID string, cmd *cobra.Command) (*ariesdid.Doc, []vdrapi.DIDMethodOption, error) {
	opts := getSidetreeURL(cmd)

	didDoc, err := getPublicKeys(cmd)
	if err != nil {
		return nil, nil, err
	}

	services, err := getServices(cmd)
	if err != nil {
		return nil, nil, err
	}

	didDoc.ID = didID
	didDoc.Service = services

	return didDoc, opts, nil
}

func getServices(cmd *cobra.Command) ([]ariesdid.Service, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addServiceFileFlagName,
		addServiceFileEnvKey)

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
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addPublicKeyFileFlagName,
		addPublicKeyFileEnvKey)

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
	startCmd.Flags().StringP(addPublicKeyFileFlagName, "", "", addPublicKeyFileFlagUsage)
	startCmd.Flags().StringP(addServiceFileFlagName, "", "", addServiceFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFlagName, "", "", nextUpdateKeyFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFileFlagName, "", "", nextUpdateKeyFileFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLOpsFlagName, "", []string{}, sidetreeURLOpsFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLResFlagName, "", []string{}, sidetreeURLResFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
	startCmd.Flags().String(kmsStoreEndpointFlagName, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().String(signingKeyIDFlagName, "", signingKeyIDFlagUsage)
	startCmd.Flags().String(nextUpdateKeyIDFlagName, "", nextUpdateKeyIDFlagUsage)
}

type keyRetriever struct {
	nextUpdateKey      crypto.PublicKey
	signingKey         crypto.PublicKey
	signingKeyID       string
	webKmsCryptoClient webcrypto.Crypto
	signingKeyPK       crypto.PublicKey
}

func (k *keyRetriever) GetNextRecoveryPublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return nil, nil
}

func (k *keyRetriever) GetNextUpdatePublicKey(didID, commitment string) (crypto.PublicKey, error) {
	return k.nextUpdateKey, nil
}

func (k *keyRetriever) GetSigner(didID string, ot orb.OperationType, commitment string) (api.Signer, error) {
	return common.NewSigner(k.signingKey, k.signingKeyID, k.webKmsCryptoClient, k.signingKeyPK), nil
}
