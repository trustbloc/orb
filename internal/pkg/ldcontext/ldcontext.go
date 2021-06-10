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

	"github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
)

const testdataDir = "testdata"

// nolint: gochecknoglobals
var (
	//go:embed testdata/*.json
	fs embed.FS

	contexts []jsonld.ContextDocument
	once     sync.Once
	errOnce  error

	defaultContexts = []string{
		"https://trustbloc.github.io/did-method-orb/contexts/anchor/v1",
	}
)

// GetAll returns all predefined contexts.
func GetAll() ([]jsonld.ContextDocument, error) {
	once.Do(func() {
		var entries []os.DirEntry

		entries, errOnce = fs.ReadDir(testdataDir)
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
			content, errOnce = fs.ReadFile(testdataDir + "/" + file.Name())
			if errOnce != nil {
				return
			}

			var doc jsonld.ContextDocument

			errOnce = json.Unmarshal(content, &doc)
			if errOnce != nil {
				return
			}

			contexts = append(contexts, doc)
		}
	})

	return append(contexts[:0:0], contexts...), errOnce
}

// MustGetDefault returns all default contexts.
func MustGetDefault() []jsonld.ContextDocument {
	var result []jsonld.ContextDocument

	for _, doc := range MustGetAll() {
		if contains(defaultContexts, doc.URL) {
			result = append(result, doc)
		}
	}

	return result
}

// MustGetExtra returns all extra contexts.
func MustGetExtra() []jsonld.ContextDocument {
	var result []jsonld.ContextDocument

	for _, doc := range MustGetAll() {
		if !contains(defaultContexts, doc.URL) {
			result = append(result, doc)
		}
	}

	return result
}

// MustGetAll returns all predefined contexts.
func MustGetAll() []jsonld.ContextDocument {
	docs, err := GetAll()
	if err != nil {
		panic(err)
	}

	return docs
}

func contains(l []string, e string) bool {
	for _, s := range l {
		if s == e {
			return true
		}
	}

	return false
}
