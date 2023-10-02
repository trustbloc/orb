/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdidcmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/spf13/cobra"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/internal/pkg/tlsutil"
)

const (
	domainFlagName      = "domain"
	domainFileEnvKey    = "ORB_CLI_DOMAIN"
	domainFileFlagUsage = "URL to the did:orb domain. " +
		" Alternatively, this can be set with the following environment variable: " + domainFileEnvKey

	sidetreeURLFlagName  = "sidetree-url"
	sidetreeURLFlagUsage = "Comma-Separated list of sidetree url." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeURLEnvKey
	sidetreeURLEnvKey = "ORB_CLI_SIDETREE_URL"

	kmsStoreEndpointFlagName  = "kms-store-endpoint"
	kmsStoreEndpointFlagUsage = "Remote KMS URL." +
		" Alternatively, this can be set with the following environment variable: " + kmsStoreEndpointEnvKey
	kmsStoreEndpointEnvKey = "ORB_CLI_KMS_STORE_ENDPOINT"

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

	recoveryKeyFlagName  = "recoverykey"
	recoveryKeyEnvKey    = "ORB_CLI_RECOVERYKEY"
	recoveryKeyFlagUsage = "The public key PEM used for recovery of the document." +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyEnvKey

	recoveryKeyFileFlagName  = "recoverykey-file"
	recoveryKeyFileEnvKey    = "ORB_CLI_RECOVERYKEY_FILE" //nolint:gosec
	recoveryKeyFileFlagUsage = "The file that contains the public key PEM used for recovery of the document." +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyFileEnvKey

	recoveryKeyIDFlagName  = "recoverykey-id"
	recoveryKeyIDEnvKey    = "ORB_CLI_RECOVERYKEY_ID"
	recoveryKeyIDFlagUsage = "The key id in kms." +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyIDEnvKey

	updateKeyFlagName  = "updatekey"
	updateKeyEnvKey    = "ORB_CLI_UPDATEKEY"
	updateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + updateKeyEnvKey

	updateKeyFileFlagName  = "updatekey-file"
	updateKeyFileEnvKey    = "ORB_CLI_UPDATEKEY_FILE"
	updateKeyFileFlagUsage = "The file that contains the public key PEM used for" +
		" validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + updateKeyFileEnvKey

	updateKeyIDFlagName  = "updatekey-id"
	updateKeyIDEnvKey    = "ORB_CLI_UPDATEKEY_ID"
	updateKeyIDFlagUsage = "The key id in kms used for" +
		" validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + updateKeyIDEnvKey

	didAnchorOriginFlagName  = "did-anchor-origin"
	didAnchorOriginEnvKey    = "ORB_CLI_DID_ANCHOR_ORIGIN"
	didAnchorOriginFlagUsage = "did anchor origin " +
		" Alternatively, this can be set with the following environment variable: " + didAnchorOriginEnvKey

	didAlsoKnownAsFlagName  = "did-also-known-as"
	didAlsoKnownAsFlagUsage = "Comma-separated list of also known as uris." +
		" Alternatively, this can be set with the following environment variable: " + didAlsoKnownAsEnvKey
	didAlsoKnownAsEnvKey = "ORB_CLI_DID_ALSO_KNOWN_AS"
)

// GetCreateDIDCmd returns the Cobra create did command.
func GetCreateDIDCmd() *cobra.Command {
	createDIDCmd := createDIDCmd()

	createFlags(createDIDCmd)

	return createDIDCmd
}

func createDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "create",
		Short:        "Create Orb DID",
		Long:         "Create Orb DID",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
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
			if kmsStoreURL != "" {
				webKmsClient = webkms.New(kmsStoreURL, &httpClient)
			}

			vdr, err := orb.New(nil, orb.WithAuthToken(sidetreeWriteToken), orb.WithDomain(domain),
				orb.WithHTTPClient(&httpClient))
			if err != nil {
				return err
			}

			didDoc, opts, err := createDIDOption(cmd, webKmsClient)
			if err != nil {
				return err
			}

			docResolution, err := vdr.Create(didDoc, opts...)
			if err != nil {
				return fmt.Errorf("failed to create did: %w", err)
			}

			bytes, err := docResolution.DIDDocument.JSONBytes()
			if err != nil {
				return err
			}

			fmt.Println(string(bytes))

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []vdrapi.DIDMethodOption {
	var opts []vdrapi.DIDMethodOption

	sidetreeURL := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey)

	if len(sidetreeURL) > 0 {
		opts = append(opts, vdrapi.WithOption(orb.OperationEndpointsOpt, sidetreeURL))
	}

	return opts
}

func createDIDOption(cmd *cobra.Command, webKmsClient kms.KeyManager) (*did.Doc, []vdrapi.DIDMethodOption, error) {
	opts := getSidetreeURL(cmd)

	didDoc, err := getPublicKeys(cmd)
	if err != nil {
		return nil, nil, err
	}

	var recoveryKey interface{}

	var updateKey interface{}

	if webKmsClient == nil { //nolint: nestif
		recoveryKey, err = common.GetKey(cmd, recoveryKeyFlagName, recoveryKeyEnvKey, recoveryKeyFileFlagName,
			recoveryKeyFileEnvKey, nil, false)
		if err != nil {
			return nil, nil, err
		}

		updateKey, err = common.GetKey(cmd, updateKeyFlagName, updateKeyEnvKey, updateKeyFileFlagName,
			updateKeyFileEnvKey, nil, false)
		if err != nil {
			return nil, nil, err
		}
	} else {
		recoveryKey, err = common.GetPublicKeyFromKMS(cmd, recoveryKeyIDFlagName, recoveryKeyIDEnvKey, webKmsClient)
		if err != nil {
			return nil, nil, err
		}

		updateKey, err = common.GetPublicKeyFromKMS(cmd, updateKeyIDFlagName, updateKeyIDEnvKey, webKmsClient)
		if err != nil {
			return nil, nil, err
		}
	}

	opts = append(opts, vdrapi.WithOption(orb.RecoveryPublicKeyOpt, recoveryKey),
		vdrapi.WithOption(orb.UpdatePublicKeyOpt, updateKey))

	services, err := getServices(cmd)
	if err != nil {
		return nil, nil, err
	}

	didDoc.Service = services

	alsoKnownAs := cmdutil.GetUserSetOptionalVarFromArrayString(cmd, didAlsoKnownAsFlagName,
		didAlsoKnownAsEnvKey)

	if len(alsoKnownAs) > 0 {
		didDoc.AlsoKnownAs = alsoKnownAs
	}

	didAnchorOrigin, err := cmdutil.GetUserSetVarFromString(cmd, didAnchorOriginFlagName,
		didAnchorOriginEnvKey, false)
	if err != nil {
		return nil, nil, err
	}

	opts = append(opts, vdrapi.WithOption(orb.AnchorOriginOpt, didAnchorOrigin))

	return didDoc, opts, nil
}

func getServices(cmd *cobra.Command) ([]did.Service, error) {
	serviceFile := cmdutil.GetUserSetOptionalVarFromString(cmd, serviceFileFlagName,
		serviceFileEnvKey)

	var svc []did.Service

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		svc = append(svc, services...)
	}

	return svc, nil
}

func getPublicKeys(cmd *cobra.Command) (*did.Doc, error) {
	publicKeyFile := cmdutil.GetUserSetOptionalVarFromString(cmd, publicKeyFileFlagName,
		publicKeyFileEnvKey)

	if publicKeyFile != "" {
		return common.GetVDRPublicKeysFromFile(publicKeyFile)
	}

	return &did.Doc{}, nil
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
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(publicKeyFileFlagName, "", "", publicKeyFileFlagUsage)
	startCmd.Flags().StringP(serviceFileFlagName, "", "", serviceFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFlagName, "", "", recoveryKeyFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFileFlagName, "", "", recoveryKeyFileFlagUsage)
	startCmd.Flags().StringP(updateKeyFlagName, "", "", updateKeyFlagUsage)
	startCmd.Flags().StringP(updateKeyFileFlagName, "", "", updateKeyFileFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
	startCmd.Flags().StringP(didAnchorOriginFlagName, "", "", didAnchorOriginFlagUsage)
	startCmd.Flags().StringArrayP(didAlsoKnownAsFlagName, "", []string{}, didAlsoKnownAsFlagUsage)
	startCmd.Flags().String(kmsStoreEndpointFlagName, "", kmsStoreEndpointFlagUsage)
	startCmd.Flags().String(updateKeyIDFlagName, "", updateKeyIDFlagUsage)
	startCmd.Flags().String(recoveryKeyIDFlagName, "", recoveryKeyIDFlagUsage)
}
