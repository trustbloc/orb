/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package writer

import (
	"fmt"

	"github.com/trustbloc/edge-core/pkg/log"
)

var logger = log.New("cas-writer")

// CasWriter is CAS writer.
type CasWriter struct {
	coreCasWriter casWriter
	hint          string
}

type casWriter interface {
	Write(content []byte) (string, error)
}

// New creates cas writer.
func New(writer casWriter, hint string) *CasWriter {
	return &CasWriter{coreCasWriter: writer, hint: hint}
}

// Write writes the given content to CAS.
// returns cid (which represents the address of the content within this CAS) plus hint.
func (cw *CasWriter) Write(content []byte) (string, string, error) {
	cid, err := cw.coreCasWriter.Write(content)
	if err != nil {
		return "", "", fmt.Errorf("failed to write to core cas: %w", err)
	}

	logger.Debugf("added content returned cid: %s", cid)

	return cid, cw.hint, nil
}
