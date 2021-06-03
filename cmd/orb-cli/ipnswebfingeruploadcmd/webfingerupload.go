/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipnswebfingeruploadcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
	files "github.com/ipfs/go-ipfs-files"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
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

	webFingerDirFlagName  = "webfinger-input-dir"
	webFingerDirFlagUsage = "webfinger input dir." +
		" Alternatively, this can be set with the following environment variable: " + webFingerDirEnvKey
	webFingerDirEnvKey = "ORB_CLI_WEBFINGER_INPUT_DIR"
)

const (
	timeout = 180
)

type object struct {
	Hash string
}

// GetCmd returns the Cobra webfinger upload command.
func GetCmd() *cobra.Command {
	cmd := webFingerGenCmd()

	createFlags(cmd)

	return cmd
}

func webFingerGenCmd() *cobra.Command { //nolint: funlen
	return &cobra.Command{
		Use:   "webfinger-upload",
		Short: "upload IPNS web finger document",
		Long:  "upload IPNS web finger document",
		RunE: func(cmd *cobra.Command, args []string) error {
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

			contentHash, err := addDir(ipfs, webFingerDir)
			if err != nil {
				return fmt.Errorf("failed to add ipfs dir: %w", err)
			}

			publishResponse, err := ipfs.PublishWithDetails(contentHash, keyName, 0, 0, true)
			if err != nil {
				return fmt.Errorf("failed to publish webfinger: %w", err)
			}

			fmt.Printf("ipns hash: %s\n", publishResponse.Name)

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(ipfsURLFlagName, "", "", ipfsURLFlagUsage)
	startCmd.Flags().StringP(keyNameFlagName, "", "", keyNameFlagUsage)
	startCmd.Flags().StringP(webFingerDirFlagName, "", "", webFingerDirFlagUsage)
}

// addDir adds a directory recursively with all of the files under it.
func addDir(ipfs *shell.Shell, dir string) (string, error) {
	stat, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}

	// https://github.com/ipfs/go-ipfs-api/pull/109
	sf, err := files.NewSerialFile(dir, true, stat)
	if err != nil {
		return "", err
	}

	slf := files.NewSliceDirectory([]files.DirEntry{files.FileEntry(filepath.Base(dir), sf)})

	reader := files.NewMultiFileReader(slf, true)

	resp, err := ipfs.Request("add").
		Option("recursive", true).Option("pin", true).
		Body(reader).
		Send(context.Background())
	if err != nil {
		return "", err
	}

	defer func() {
		if errClose := resp.Close(); errClose != nil {
			panic(errClose.Error())
		}
	}()

	if resp.Error != nil {
		return "", resp.Error
	}

	dec := json.NewDecoder(resp.Output)

	var final string

	for {
		var out object

		err = dec.Decode(&out)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return "", err
		}

		final = out.Hash
	}

	if final == "" {
		return "", errors.New("no results received")
	}

	return final, nil
}
