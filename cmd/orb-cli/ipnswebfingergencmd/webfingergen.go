/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipnswebfingergencmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

	webFingerDirFlagName  = "webfinger-output-dir"
	webFingerDirFlagUsage = "webfinger output dir." +
		" Alternatively, this can be set with the following environment variable: " + webFingerDirEnvKey
	webFingerDirEnvKey = "ORB_CLI_WEBFINGER_OUTPUT_DIR"
)

const (
	timeout = 2
)

// GetCmd returns the Cobra webfinger gent command.
func GetCmd() *cobra.Command {
	cmd := webFingerGenCmd()

	createFlags(cmd)

	return cmd
}

func webFingerGenCmd() *cobra.Command { //nolint: funlen,gocyclo,cyclop,gocognit
	return &cobra.Command{
		Use:   "webfinger-gen",
		Short: "generate IPNS web finger document",
		Long:  "generate IPNS web finger document",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			httpClient := &http.Client{
				Transport: &http.Transport{
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

			webFingerDir := cmdutils.GetUserSetOptionalVarFromString(cmd, webFingerDirFlagName,
				webFingerDirEnvKey)

			if webFingerDir == "" {
				webFingerDir = "."
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

			respBytes, err := common.SendRequest(httpClient, nil, nil, http.MethodGet,
				fmt.Sprintf("%s/.well-known/webfinger?resource=%s",
					resourceURL, url.PathEscape(resourceURL)))
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			var webFingerResp restapi.WebFingerResponse

			if errUnmarshal := json.Unmarshal(respBytes, &webFingerResp); errUnmarshal != nil {
				return errUnmarshal
			}

			webFingerResp.Subject = fmt.Sprintf("ipns://%s", keyID)

			webFingerBytes, err := json.Marshal(webFingerResp)
			if err != nil {
				return err
			}

			if errMkdir := os.MkdirAll(fmt.Sprintf("%s/website/.well-known", webFingerDir), os.ModePerm); errMkdir != nil {
				return errMkdir
			}

			webFingerFile := fmt.Sprintf("%s/website/.well-known/webfinger", webFingerDir)

			f, err := os.Create(webFingerFile)
			if err != nil {
				return err
			}

			_, err = f.Write(webFingerBytes)
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
	startCmd.Flags().StringP(webFingerDirFlagName, "", "", webFingerDirFlagUsage)
	startCmd.Flags().StringP(resourceURLFlagName, "", "", resourceURLFlagUsage)
}
