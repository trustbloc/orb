/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/activitypub/service/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestNewHandler(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := newHandler("", cfg, memstore.New(""),
		func(writer http.ResponseWriter, request *http.Request) {},
		&mocks.SignatureVerifier{}, pageNumParam, pageParam,
	)

	require.NotNil(t, h)
	require.Equal(t, basePath, h.Path())
	require.Equal(t, http.MethodGet, h.Method())
	require.NotNil(t, h.Handler())
	require.Equal(t, "{page}", h.Params()[pageParam])
	require.Equal(t, "{page-num}", h.Params()[pageNumParam])
}

func TestGetFirstPageNum(t *testing.T) {
	t.Run("Sort ascending", func(t *testing.T) {
		require.Equal(t, 0, getFirstPageNum(10, 3, spi.SortAscending))
	})

	t.Run("Sort descending", func(t *testing.T) {
		require.Equal(t, 0, getFirstPageNum(9, 20, spi.SortDescending))
		require.Equal(t, 2, getFirstPageNum(9, 3, spi.SortDescending))
		require.Equal(t, 3, getFirstPageNum(10, 3, spi.SortDescending))
	})
}

func TestGetLastPageNum(t *testing.T) {
	t.Run("Sort ascending", func(t *testing.T) {
		require.Equal(t, 3, getLastPageNum(10, 3, spi.SortAscending))
		require.Equal(t, 2, getLastPageNum(9, 3, spi.SortAscending))
	})

	t.Run("Sort descending", func(t *testing.T) {
		require.Equal(t, 0, getLastPageNum(9, 20, spi.SortDescending))
		require.Equal(t, 0, getLastPageNum(10, 3, spi.SortDescending))
	})
}

func TestGetCurrentPrevNext(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := newHandler("", cfg, memstore.New(""), nil, &mocks.SignatureVerifier{})

	t.Run("Sort ascending", func(t *testing.T) {
		t.Run("No page-num", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: -1,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.Equal(t, 0, current)
			require.Equal(t, -1, prev)
			require.Equal(t, 1, next)
		})

		t.Run("Page-num specified", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: 1,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.Equal(t, 1, current)
			require.Equal(t, 0, prev)
			require.Equal(t, 2, next)
		})

		t.Run("Page-num too large", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: 10,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.Equal(t, 10, current)
			require.Equal(t, 2, prev)
			require.Equal(t, -1, next)
		})
	})

	t.Run("Sort descending", func(t *testing.T) {
		t.Run("No page-num", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: -1,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.Equal(t, 2, current)
			require.Equal(t, -1, prev)
			require.Equal(t, 1, next)
		})

		t.Run("Page-num specified", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: 1,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.Equal(t, 1, current)
			require.Equal(t, 2, prev)
			require.Equal(t, 0, next)
		})

		t.Run("Page-num too large", func(t *testing.T) {
			current, prev, next := h.getCurrentPrevNext(10,
				&spi.QueryOptions{
					PageNumber: 10,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.Equal(t, 10, current)
			require.Equal(t, -1, prev)
			require.Equal(t, 2, next)
		})
	})
}

func TestGetIDPrevNextURL(t *testing.T) {
	cfg := &Config{
		BasePath:  basePath,
		ObjectIRI: serviceIRI,
		PageSize:  4,
	}

	h := newHandler("", cfg, memstore.New(""), nil, &mocks.SignatureVerifier{})

	id := testutil.MustParseURL(fmt.Sprintf("%s%s", cfg.ObjectIRI, ""))

	t.Run("Sort ascending", func(t *testing.T) {
		t.Run("No page-num", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: -1,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=0", pageID.String())
			require.Nil(t, prev)
			require.NotNil(t, next)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=1", next.String())
		})

		t.Run("Page-num specified", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: 1,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=1", pageID.String())
			require.NotNil(t, prev)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=0", prev.String())
			require.NotNil(t, next)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=2", next.String())
		})

		t.Run("Page-num too large", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: 10,
					PageSize:   4,
					SortOrder:  spi.SortAscending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=10", pageID.String())
			require.NotNil(t, prev)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=2", prev.String())
			require.Nil(t, next)
		})
	})

	t.Run("Sort descending", func(t *testing.T) {
		t.Run("No page-num", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: -1,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=2", pageID.String())
			require.Nil(t, prev)
			require.NotNil(t, next)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=1", next.String())
		})

		t.Run("Page-num specified", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: 1,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=1", pageID.String())
			require.NotNil(t, prev)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=2", prev.String())
			require.NotNil(t, next)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=0", next.String())
		})

		t.Run("Page-num too large", func(t *testing.T) {
			pageID, prev, next, err := h.getIDPrevNextURL(id, 10,
				&spi.QueryOptions{
					PageNumber: 10,
					PageSize:   4,
					SortOrder:  spi.SortDescending,
				},
			)
			require.NoError(t, err)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=10", pageID.String())
			require.Nil(t, prev)
			require.NotNil(t, next)
			require.Equal(t, "https://example1.com/services/orb?page=true&page-num=2", next.String())
		})
	})
}

func newMockCreateActivities(num int) []*vocab.ActivityType {
	activities := make([]*vocab.ActivityType, num)

	for i := 0; i < num; i++ {
		activities[i] = newMockCreateActivity(fmt.Sprintf("https://activity_%d", i), fmt.Sprintf("https://obj_%d", i))
	}

	return activities
}

func newMockCreateActivity(id, objID string) *vocab.ActivityType {
	return vocab.NewCreateActivity(
		vocab.NewObjectProperty(
			vocab.WithAnchorCredentialReference(
				vocab.NewAnchorCredentialReference(
					testutil.MustParseURL(objID),
					testutil.MustParseURL("https://example.com/cas/bafkd34G7hD6gbj94fnKm5D"),
					"bafkd34G7hD6gbj94fnKm5D"),
			),
		),
		vocab.WithID(testutil.MustParseURL(id)),
	)
}

func setPaging(h *handler, page, pageNum string) func() {
	getParamsRestore := h.getParams

	h.getParams = func(req *http.Request) map[string][]string {
		return map[string][]string{
			pageParam:    {page},
			pageNumParam: {pageNum},
		}
	}

	return func() {
		h.getParams = getParamsRestore
	}
}

func setIDParam(id string) func() {
	restore := getIDParam

	getIDParam = func(req *http.Request) string {
		return id
	}

	return func() {
		getIDParam = restore
	}
}
