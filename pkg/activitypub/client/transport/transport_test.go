/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/client/mocks"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

//go:generate counterfeiter -o ../mocks/httpclient.gen.go --fake-name HTTPClient . httpClient
//go:generate counterfeiter -o ../mocks/httpsigner.gen.go --fake-name HTTPSigner . Signer

const publicKeyID = "https://alice.example.com/services/orb/keys/main-key"

func TestNew(t *testing.T) {
	tp := New(http.DefaultClient, testutil.MustParseURL(publicKeyID), DefaultSigner(), DefaultSigner())
	require.NotNil(t, tp)
}

func TestNewRequest(t *testing.T) {
	req := NewRequest(
		testutil.MustParseURL("https://someurl"),
		WithHeader(AcceptHeader, ActivityStreamsContentType),
	)
	require.NotNil(t, req)
	require.Equal(t, []string{ActivityStreamsContentType}, req.Header[AcceptHeader])
}

func TestDefault(t *testing.T) {
	require.NotNil(t, Default())
}

func TestTransport_Post(t *testing.T) {
	resp := &http.Response{}

	httpClient := &mocks.HTTPClient{}
	httpClient.DoReturns(resp, nil)

	t.Run("Success", func(t *testing.T) {
		tp := New(httpClient, testutil.MustParseURL(publicKeyID), DefaultSigner(), DefaultSigner())
		require.NotNil(t, tp)

		req := NewRequest(testutil.MustParseURL("https://domain1.com"))
		req.Header["some-header"] = []string{"some value"}

		//nolint:bodyclose
		resp, err := tp.Post(context.Background(), req, []byte("payload"))
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("Sign error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected signer error")

		signer := &mocks.HTTPSigner{}
		signer.SignRequestReturns(errExpected)

		tp := New(httpClient, testutil.MustParseURL(publicKeyID), signer, signer)
		require.NotNil(t, tp)

		//nolint:bodyclose
		resp, err := tp.Post(context.Background(),
			NewRequest(testutil.MustParseURL("https://domain1.com")), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, resp)
	})
}

func TestTransport_Get(t *testing.T) {
	resp := &http.Response{}

	httpClient := &mocks.HTTPClient{}
	httpClient.DoReturns(resp, nil)

	t.Run("Success", func(t *testing.T) {
		tp := New(httpClient, testutil.MustParseURL(publicKeyID), DefaultSigner(), DefaultSigner())
		require.NotNil(t, tp)

		req := NewRequest(testutil.MustParseURL("https://domain1.com"))
		req.Header["some-header"] = []string{"some value"}

		//nolint:bodyclose
		resp, err := tp.Get(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("Sign error", func(t *testing.T) {
		errExpected := fmt.Errorf("injected signer error")

		signer := &mocks.HTTPSigner{}
		signer.SignRequestReturns(errExpected)

		tp := New(httpClient, testutil.MustParseURL(publicKeyID), signer, signer)
		require.NotNil(t, tp)

		//nolint:bodyclose
		resp, err := tp.Get(context.Background(),
			NewRequest(testutil.MustParseURL("https://domain1.com")))
		require.Error(t, err)
		require.Contains(t, err.Error(), errExpected.Error())
		require.Nil(t, resp)
	})
}
