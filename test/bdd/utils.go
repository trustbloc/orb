/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
)

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func executeCMD(path string, args ...string) (string, error) {
	cmd := exec.Command(path, args...)

	var out bytes.Buffer

	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}

	return out.String(), nil
}

func readZip(b []byte) (io.Reader, error) {
	zipReader, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return nil, e
	}

	// Read all the files from zip archive
	for _, zipFile := range zipReader.File {
		logger.Infof("Reading file from ZIP: [%s]", zipFile.Name)

		unzippedFileBytes, e := readZipFile(zipFile)
		if e != nil {
			return nil, e
		}

		return bytes.NewReader(unzippedFileBytes), nil
	}

	return nil, errors.New("no files found in ZIP")
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}
