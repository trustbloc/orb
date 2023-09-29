/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package extendedcasclient

import casapi "github.com/trustbloc/sidetree-svc-go/pkg/api/cas"

// CIDFormatOption is an option for specifying the CID format used in a WriteWithCIDFormat call.
type CIDFormatOption func(opts *CIDFormatOptions)

// CIDFormatOptions represent CID format options for use in a Client.WriteWithCIDFormat call.
type CIDFormatOptions struct {
	CIDVersion int
}

// WithCIDVersion sets the CID version to be used in a WriteWithCIDFormat call.
// Currently, 0 and 1 are the only valid options.
func WithCIDVersion(cidVersion int) CIDFormatOption {
	return func(opts *CIDFormatOptions) {
		opts.CIDVersion = cidVersion
	}
}

// Client represents a CAS client with an additional method that allows the CID format
// to be specified for a specific write.
type Client interface {
	casapi.Client
	WriteWithCIDFormat(content []byte, opts ...CIDFormatOption) (string, error)
	GetPrimaryWriterType() string
}
