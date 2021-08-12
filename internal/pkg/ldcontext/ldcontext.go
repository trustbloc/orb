/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ldcontext

import (
	"embed"
	"encoding/json"
	"os"
	"sync"

	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
)

const payloadDir = "payload"

// nolint: gochecknoglobals
var (
	//go:embed payload/*.json
	fs embed.FS

	contexts []ldcontext.Document
	once     sync.Once
	errOnce  error
)

// GetAll returns all predefined contexts.
func GetAll() ([]ldcontext.Document, error) {
	once.Do(func() {
		var entries []os.DirEntry

		entries, errOnce = fs.ReadDir(payloadDir)
		if errOnce != nil {
			return
		}

		for _, entry := range entries {
			var file os.FileInfo
			file, errOnce = entry.Info()
			if errOnce != nil {
				return
			}

			var content []byte
			// Do not use os.PathSeparator here, we are using go:embed to load files.
			// The path separator is a forward slash, even on Windows systems.
			content, errOnce = fs.ReadFile(payloadDir + "/" + file.Name())
			if errOnce != nil {
				return
			}

			var doc ldcontext.Document

			errOnce = json.Unmarshal(content, &doc)
			if errOnce != nil {
				return
			}

			contexts = append(contexts, doc)
		}
	})

	return append(contexts[:0:0], contexts...), errOnce
}

// MustGetAll returns all predefined contexts.
func MustGetAll() []ldcontext.Document {
	docs, err := GetAll()
	if err != nil {
		panic(err)
	}

	return docs
}
