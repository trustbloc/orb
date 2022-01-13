/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipnshostmetagencmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/pkg/discovery/endpoint/restapi"
)

const (
	ipfsURLFlagName  = "ipfs-url"
	ipfsURLFlagUsage = "IPFS url." +
		" Alternatively, this can be set with the following environment variable: " + ipfsURLEnvKey
	ipfsURLEnvKey = "ORB_CLI_IPFS_URL"

	resourceURLFlagName  = "resource-url"
	resourceURLFlagUsage = "resource url." +
		" Alternatively, this can be set with the following environment variable: " + resourceURLEnvKey
	resourceURLEnvKey = "ORB_CLI_RESOURCE_URL"

	keyNameFlagName  = "key-name"
	keyNameFlagUsage = "key name." +
		" Alternatively, this can be set with the following environment variable: " + keyNameEnvKey
	keyNameEnvKey = "ORB_CLI_KEY_NAME"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "ORB_CLI_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "ORB_CLI_TLS_CACERTS"

	hostMetaDocOutputPathFlagName  = "host-meta-dir-output-path"
	hostMetaDocOutputPathFlagUsage = "Host-meta dir output path." +
		" Alternatively, this can be set with the following environment variable: " + hostMetaDocOutputPathEnvKey
	hostMetaDocOutputPathEnvKey = "ORB_CLI_HOST_META_DOC_OUTPUT_PATH"
)

const (
	timeout = 2
)

// GetCmd returns the Cobra host-meta document gen command.
func GetCmd() *cobra.Command {
	cmd := hostMetaGenCmd()

	createFlags(cmd)

	return cmd
}

func hostMetaGenCmd() *cobra.Command { //nolint: funlen,gocyclo,cyclop
	return &cobra.Command{
		Use:   "host-meta-doc-gen",
		Short: "generate IPNS host-meta document",
		Long:  "generate IPNS host-meta document",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					TLSClientConfig: &tls.Config{
						RootCAs:    rootCAs,
						MinVersion: tls.VersionTLS12,
					},
				},
			}

			ipfsURL, err := cmdutils.GetUserSetVarFromString(cmd, ipfsURLFlagName,
				ipfsURLEnvKey, false)
			if err != nil {
				return err
			}

			resourceURL, err := cmdutils.GetUserSetVarFromString(cmd, resourceURLFlagName,
				resourceURLEnvKey, false)
			if err != nil {
				return err
			}

			keyName, err := cmdutils.GetUserSetVarFromString(cmd, keyNameFlagName,
				keyNameEnvKey, false)
			if err != nil {
				return err
			}

			hostMetaDirOutputPath := cmdutils.GetUserSetOptionalVarFromString(cmd, hostMetaDocOutputPathFlagName,
				hostMetaDocOutputPathEnvKey)

			if hostMetaDirOutputPath == "" {
				hostMetaDirOutputPath = "."
			}

			ipfs := shell.NewShell(ipfsURL)

			ipfs.SetTimeout(timeout * time.Second)

			keyList, err := ipfs.KeyList(context.Background())
			if err != nil {
				return err
			}

			keyID := ""

			for _, v := range keyList {
				if v.Name == keyName {
					keyID = v.Id

					break
				}
			}

			if keyID == "" {
				return fmt.Errorf("key %s not found in IPFS", keyName)
			}

			headers := map[string]string{"Accept": "application/json"}

			hostMetaDocBytes, err := common.SendRequest(httpClient, nil, headers, http.MethodGet,
				fmt.Sprintf("%s%s", resourceURL, restapi.HostMetaJSONEndpoint))
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			if errMkdir := os.MkdirAll(fmt.Sprintf("%s/website/.well-known", hostMetaDirOutputPath),
				os.ModePerm); errMkdir != nil {
				return errMkdir
			}

			hostMetaFilePath := fmt.Sprintf("%s/website/.well-known/host-meta.json", hostMetaDirOutputPath)

			f, err := os.Create(hostMetaFilePath)
			if err != nil {
				return err
			}

			_, err = f.Write(hostMetaDocBytes)
			if err != nil {
				return err
			}

			defer func() {
				if errClose := f.Close(); errClose != nil {
					panic(errClose.Error())
				}
			}()

			return nil
		},
	}
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
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(ipfsURLFlagName, "", "", ipfsURLFlagUsage)
	startCmd.Flags().StringP(keyNameFlagName, "", "", keyNameFlagUsage)
	startCmd.Flags().StringP(hostMetaDocOutputPathFlagName, "", "", hostMetaDocOutputPathFlagUsage)
	startCmd.Flags().StringP(resourceURLFlagName, "", "", resourceURLFlagUsage)
}
