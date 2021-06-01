/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipfskeygencmd

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"

	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
)

const (
	ipfsURLFlagName  = "ipfs-url"
	ipfsURLFlagUsage = "IPFS url." +
		" Alternatively, this can be set with the following environment variable: " + ipfsURLEnvKey
	ipfsURLEnvKey = "ORB_CLI_IPFS_URL"

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

	keyDirFlagName  = "key-output-dir"
	keyDirFlagUsage = "key output dir." +
		" Alternatively, this can be set with the following environment variable: " + keyDirEnvKey
	keyDirEnvKey = "ORB_CLI_KEY_OUTPUT_DIR"
)

// GetCmd returns the Cobra follow command.
func GetCmd() *cobra.Command {
	cmd := keyGenCmd()

	createFlags(cmd)

	return cmd
}

func keyGenCmd() *cobra.Command { //nolint: funlen,gocyclo,cyclop
	return &cobra.Command{
		Use:   "key-gen",
		Short: "generate IPFS key",
		Long:  "generate IPFS key ",
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

			keyName, err := cmdutils.GetUserSetVarFromString(cmd, keyNameFlagName,
				keyNameEnvKey, false)
			if err != nil {
				return err
			}

			keyDir := cmdutils.GetUserSetOptionalVarFromString(cmd, keyDirFlagName,
				keyDirEnvKey)

			priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
			if err != nil {
				return err
			}

			encoded, err := crypto.MarshalPrivateKey(priv)
			if err != nil {
				return err
			}

			if keyDir == "" {
				keyDir = "."
			}

			keyFile := fmt.Sprintf("%s/%s.key", keyDir, keyName)

			f, err := os.Create(keyFile)
			if err != nil {
				return err
			}

			_, err = f.Write(encoded)
			if err != nil {
				return err
			}

			defer func() {
				if errClose := f.Close(); errClose != nil {
					panic(errClose.Error())
				}
			}()

			b, w, err := createMultipartFormData("key", keyFile)
			if err != nil {
				return err
			}

			importKeyURL := fmt.Sprintf("%s/api/v0/key/import?arg=%s", ipfsURL, keyName)

			headers := make(map[string]string)
			headers["Content-Type"] = w.FormDataContentType()

			_, err = common.SendRequest(httpClient, b.Bytes(), headers, http.MethodPost,
				importKeyURL)
			if err != nil {
				return fmt.Errorf("failed to send http request: %w", err)
			}

			return nil
		},
	}
}

func createMultipartFormData(fieldName, fileName string) (*bytes.Buffer, *multipart.Writer, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	var fw io.Writer

	file, err := os.Open(fileName) // nolint: gosec
	if err != nil {
		return nil, nil, err
	}

	if fw, err = w.CreateFormFile(fieldName, file.Name()); err != nil {
		return nil, nil, err
	}

	if _, err = io.Copy(fw, file); err != nil {
		return nil, nil, err
	}

	defer func() {
		if err := w.Close(); err != nil {
			panic(err.Error())
		}
	}()

	return &b, w, nil
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
	startCmd.Flags().StringP(keyDirFlagName, "", "", keyDirFlagUsage)
}
