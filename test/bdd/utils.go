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
	"os/exec"
	"time"
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
	return io.ReadAll(f)
}

type greylist struct {
	entries map[string]time.Time
	backoff time.Duration
}

func newGreylist(backoff time.Duration) *greylist {
	return &greylist{
		entries: make(map[string]time.Time),
		backoff: backoff,
	}
}

func (g *greylist) Add(u string) {
	g.entries[u] = time.Now().Add(g.backoff)
}

func (g *greylist) IsGreylisted(u string) bool {
	t, ok := g.entries[u]
	if !ok {
		return false
	}

	if time.Now().Before(t) {
		return true
	}

	delete(g.entries, u)

	return false
}
