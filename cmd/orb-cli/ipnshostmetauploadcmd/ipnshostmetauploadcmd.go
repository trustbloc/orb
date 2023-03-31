/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package ipnshostmetauploadcmd

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

	"github.com/trustbloc/orb/internal/pkg/cmdutil"
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

	hostMetaDocInputFileFlagName  = "host-meta-input-dir"
	hostMetaDocInputFileFlagUsage = "Host-meta input dir." +
		" Alternatively, this can be set with the following environment variable: " + hostMetaDocInputFileEnvKey
	hostMetaDocInputFileEnvKey = "ORB_CLI_HOST_META_DOC_INPUT_FILE"
)

const (
	timeout = 240
)

//nolint:musttag
type object struct {
	Hash string
}

// GetCmd returns the Cobra host-meta doc upload command.
func GetCmd() *cobra.Command {
	cmd := hostMetaDocUploadCmd()

	createFlags(cmd)

	return cmd
}

func hostMetaDocUploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "host-meta-dir-upload",
		Short:        "upload IPNS host-meta document",
		Long:         "upload IPNS host-meta document",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ipfsURL, err := cmdutil.GetUserSetVarFromString(cmd, ipfsURLFlagName,
				ipfsURLEnvKey, false)
			if err != nil {
				return err
			}

			keyName, err := cmdutil.GetUserSetVarFromString(cmd, keyNameFlagName,
				keyNameEnvKey, false)
			if err != nil {
				return err
			}

			hostMetaDocInputPath := cmdutil.GetUserSetOptionalVarFromString(cmd, hostMetaDocInputFileFlagName,
				hostMetaDocInputFileEnvKey)

			if hostMetaDocInputPath == "" {
				hostMetaDocInputPath = "."
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

			fmt.Println("Adding host-meta doc file to IPFS...")

			contentHash, err := addDir(ipfs, hostMetaDocInputPath)
			if err != nil {
				return fmt.Errorf("failed to add file to IPFS: %w", err)
			}

			fmt.Printf("Successfully added host-meta doc to IPFS. Content hash: %s\n", contentHash)

			fmt.Println("Adding host-meta doc file to IPNS... This may take several minutes...")

			publishResponse, err := ipfs.PublishWithDetails(contentHash, keyName, 0, 0, true)
			if err != nil {
				return fmt.Errorf("failed to publish meta-host doc to IPNS: %w", err)
			}

			fmt.Printf("Successfully added host-meta doc to IPNS. "+
				"It's located at /ipns/%s/.well-known/host-meta.json\n", publishResponse.Name)

			return nil
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(ipfsURLFlagName, "", "", ipfsURLFlagUsage)
	startCmd.Flags().StringP(keyNameFlagName, "", "", keyNameFlagUsage)
	startCmd.Flags().StringP(hostMetaDocInputFileFlagName, "", "", hostMetaDocInputFileFlagUsage)
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
