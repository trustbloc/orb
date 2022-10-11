/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package acknowlegement

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/internal/testutil"
	"github.com/trustbloc/orb/pkg/mocks"
)

var (
	actor     = testutil.MustParseURL("https://domain1.com")
	anchorRef = testutil.MustParseURL("hl:uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ:uoQ-BeDVpcGZzOi8vUW1jcTZKV0RVa3l4ZWhxN1JWWmtQM052aUU0SHFSdW5SalgzOXZ1THZFSGFRTg")

	additionalRefs = []*url.URL{
		// Valid hashlink.
		testutil.MustParseURL("hl:uEiALYp_C4wk2WegpfnCSoSTBdKZ1MVdDadn4rdmZl5GKzQ:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQlVRRFJJNXR0SXpYYmUxTFpLVWFaV2I2eUZzbk1ucmdEa3NBdFEtd0NhS3c"),
		// Hash in hashlink doesn't match anchor hash.
		testutil.MustParseURL("hl:uEiBUQDRI5ttIzXbe1LZKUaZWb6yFsnMnrgDksAtQ-wCaKw:uoQ-BeEtodHRwczovL29yYi5kb21haW4yLmNvbS9jYXMvdUVpQlVRRFJJNXR0SXpYYmUxTFpLVWFaV2I2eUZzbk1ucmdEa3NBdFEtd0NhS3c"),
		// Invalid hashlink.
		testutil.MustParseURL("xx:invalid"),
	}
)

func TestHandler_AnchorEventAcknowledged(t *testing.T) {
	linkStore := &mocks.AnchorLinkStore{}

	h := New(linkStore)

	t.Run("Success", func(t *testing.T) {
		linkStore.PutLinksReturns(nil)

		require.NoError(t, h.AnchorEventAcknowledged(actor, anchorRef, additionalRefs))
	})

	t.Run("Anchor link storage error", func(t *testing.T) {
		errExpected := errors.New("injected storage error")

		linkStore.PutLinksReturns(errExpected)

		err := h.AnchorEventAcknowledged(actor, anchorRef, additionalRefs)

		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Invalid anchor link", func(t *testing.T) {
		require.Error(t, h.AnchorEventAcknowledged(actor, testutil.MustParseURL("xx:invalid"), additionalRefs))
	})
}

func TestHandler_UndoAnchorEventAcknowledged(t *testing.T) {
	linkStore := &mocks.AnchorLinkStore{}

	h := New(linkStore)

	t.Run("Success", func(t *testing.T) {
		linkStore.DeleteLinksReturns(nil)

		require.NoError(t, h.UndoAnchorEventAcknowledgement(actor, anchorRef, additionalRefs))
	})

	t.Run("Anchor link storage error", func(t *testing.T) {
		errExpected := errors.New("injected storage error")

		linkStore.DeleteLinksReturns(errExpected)

		err := h.UndoAnchorEventAcknowledgement(actor, anchorRef, additionalRefs)

		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
	})

	t.Run("Invalid anchor link", func(t *testing.T) {
		require.Error(t, h.UndoAnchorEventAcknowledgement(actor, testutil.MustParseURL("xx:invalid"), additionalRefs))
	})
}
