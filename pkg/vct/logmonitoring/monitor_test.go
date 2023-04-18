/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/internal/testutil/mongodbtestutil"
	"github.com/trustbloc/orb/pkg/store/logentry"
	"github.com/trustbloc/orb/pkg/store/logmonitor"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testLog = "http://vct.com"

	sthURL            = "/v1/get-sth"
	getEntriesURL     = "/v1/get-entries"
	sthConsistencyURL = "/v1/get-sth-consistency"
	webfingerURL      = "/.well-known/webfinger"
)

func TestNew(t *testing.T) {
	store, err := logmonitor.New(mem.NewProvider())
	require.NoError(t, err)

	client, err := New(store, nil, map[string]string{})
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, uint64(defaultMaxTreeSize), client.maxTreeSize)
	require.Equal(t, defaultMaxGetEntriesRange, client.maxGetEntriesRange)

	client, err = New(store, nil, map[string]string{},
		WithMaxGetEntriesRange(50),
		WithMaxTreeSize(100))
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, uint64(100), client.maxTreeSize)
	require.Equal(t, 50, client.maxGetEntriesRange)
}

func TestClient_MonitorLogs(t *testing.T) {
	t.Run("success - new STH is zero tree size", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.MonitorLogs()
	})

	t.Run("success - no active logs found", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.MonitorLogs()
	})

	t.Run("success - get active logs error", func(t *testing.T) {
		store := &storemocks.Store{}
		store.QueryReturns(nil, fmt.Errorf("store error"))

		db := &storemocks.Provider{}
		db.OpenStoreReturns(store, nil)

		logMonitorStore, err := logmonitor.New(db)
		require.NoError(t, err)

		client, err := New(logMonitorStore, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.MonitorLogs()
	})

	t.Run("error - invalid signature", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": DifferentPublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.MonitorLogs()
	})
}

func TestClient_processLog(t *testing.T) {
	t.Run("success - new STH is zero tree size", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		log, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.processLog(log)
	})

	t.Run("error - invalid signature", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": DifferentPublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.processLog(&logmonitor.LogMonitor{Log: testLog})
	})
}

//nolint:gocognit,gocyclo,cyclop,maintidx
func TestClient_checkVCTConsistency(t *testing.T) {
	t.Run("success - empty stored, new STH tree size is zero", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("success - stored and new STH are same tree sizes", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth0), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("success - stored and new STH are different tree sizes (stored is zero)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth0), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
						{
							LeafInput: []byte("leafInput-1"),
						},
						{
							LeafInput: []byte("leafInput-2"),
						},
						{
							LeafInput: []byte("leafInput-3"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("success - stored and new STH are different tree sizes (stored > 0)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=4, log=0)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		entries := []command.LeafEntry{
			{
				LeafInput: []byte("leafInput-0"),
			},
			{
				LeafInput: []byte("leafInput-1"),
			},
			{
				LeafInput: []byte("leafInput-2"),
			},
			{
				LeafInput: []byte("leafInput-3"),
			},
		}

		err = s.StoreLogEntries(testLog, 0, 3, entries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{}, WithLogEntriesStoreEnabled(true), WithLogEntriesStore(s))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
						{
							LeafInput: []byte("leafInput-1"),
						},
						{
							LeafInput: []byte("leafInput-2"),
						},
						{
							LeafInput: []byte("leafInput-3"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{}, WithLogEntriesStoreEnabled(true), WithLogEntriesStore(s))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4, fetchSize=3)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				responseEntries := []command.LeafEntry{
					{
						LeafInput: []byte("leafInput-0"),
					},
					{
						LeafInput: []byte("leafInput-1"),
					},
					{
						LeafInput: []byte("leafInput-2"),
					},
					{
						LeafInput: []byte("leafInput-3"),
					},
				}

				params := req.URL.Query()

				start, e := strconv.Atoi(params["start"][0])
				require.NoError(t, e)

				end, e := strconv.Atoi(params["end"][0])
				require.NoError(t, e)

				if end+1 <= len(responseEntries) {
					end++
				}

				expected := command.GetEntriesResponse{
					Entries: responseEntries[start:end],
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(s),
			WithMaxRecoveryFetchSize(3))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4, fetchSize=1)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				responseEntries := []command.LeafEntry{
					{
						LeafInput: []byte("leafInput-0"),
					},
					{
						LeafInput: []byte("leafInput-1"),
					},
					{
						LeafInput: []byte("leafInput-2"),
					},
					{
						LeafInput: []byte("leafInput-3"),
					},
				}

				params := req.URL.Query()

				start, e := strconv.Atoi(params["start"][0])
				require.NoError(t, e)

				end, e := strconv.Atoi(params["end"][0])
				require.NoError(t, e)

				if end+1 <= len(responseEntries) {
					end++
				}

				expected := command.GetEntriesResponse{
					Entries: responseEntries[start:end],
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(s),
			WithMaxRecoveryFetchSize(1))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4, fetchSize=1)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				responseEntries := []command.LeafEntry{
					{
						LeafInput: []byte("leafInput-0"),
					},
					{
						LeafInput: []byte("leafInput-1"),
					},
					{
						LeafInput: []byte("leafInput-diff-2"),
					},
					{
						LeafInput: []byte("leafInput-diff-3"),
					},
				}

				params := req.URL.Query()

				start, e := strconv.Atoi(params["start"][0])
				require.NoError(t, e)

				end, e := strconv.Atoi(params["end"][0])
				require.NoError(t, e)

				if end+1 <= len(responseEntries) {
					end++
				}

				expected := command.GetEntriesResponse{
					Entries: responseEntries[start:end],
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(s),
			WithMaxRecoveryFetchSize(1))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size greater than log tree size"+
		"(stored=5, log=4, different=2)", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
						{
							LeafInput: []byte("leafInput-1"),
						},
						{
							LeafInput: []byte("leafInput-diff-2"),
						},
						{
							LeafInput: []byte("leafInput-diff-3"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{}, WithLogEntriesStoreEnabled(true), WithLogEntriesStore(s))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4)"+
		"error due to get entries failure", func(t *testing.T) {
		mongoDBConnString, stopMongo := mongodbtestutil.StartMongoDB(t)
		defer stopMongo()

		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		s, err := logentry.New(mongoDBProvider)
		require.NoError(t, err)

		err = s.StoreLogEntries(testLog, 0, 4, storedEntries)
		require.NoError(t, err)

		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusInternalServerError,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{}, WithLogEntriesStoreEnabled(true), WithLogEntriesStore(s))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get entries for range[0-4]")
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4)"+
		"error due to get entries from entry store failure", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{GetErr: fmt.Errorf("get entries error")}))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get entries error")
	})

	t.Run("recovery - stored tree size is greater than log tree size (stored=5, log=4)"+
		"error due to fail entries in entry store failure", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{FailErr: fmt.Errorf("fail entries error")}))
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fail entries error")
	})

	t.Run("recovery - stored and new STH are different tree sizes "+
		"(stored=5, log=4, entries store disabled)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth5), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput-0"),
						},
						{
							LeafInput: []byte("leafInput-1"),
						},
						{
							LeafInput: []byte("leafInput-2"),
						},
						{
							LeafInput: []byte("leafInput-3"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("success - empty stored, new STH tree size > 0", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{
			RootHash: sthResponse.SHA256RootHash,
		}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("error - stored > 0 and new STH are different tree sizes (get entries fails)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{}

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to verify STH consistency: get entries between trees: failed to get entries for range[4-4]")
	})

	t.Run("error - get STH error", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get STH")
	})

	t.Run("error - get STH consistency error", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusInternalServerError,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify STH consistency: get STH consistency")
	})

	t.Run("error - verify consistency proof: empty proof", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		logMonitor.STH = &sthResponse

		err = store.Update(logMonitor)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == sthConsistencyURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString("{}")),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, innerErr := json.Marshal(expected)
				require.NoError(t, innerErr)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to verify STH consistency: verify consistency proof: empty proof")
	})

	t.Run("error - invalid signature (different public key)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": DifferentPublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid signature")
	})

	t.Run("error - invalid public key", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get public key: webfinger")
	})

	t.Run("error - store update error", func(t *testing.T) {
		store := &storemocks.Store{}
		store.PutReturns(fmt.Errorf("put error"))

		db := &storemocks.Provider{}
		db.OpenStoreReturns(store, nil)

		logMonitorStore, err := logmonitor.New(db)
		require.NoError(t, err)

		client, err := New(logMonitorStore, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(&logmonitor.LogMonitor{Log: testLog})
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to store STH: failed to store log monitor: put error")
	})

	t.Run("error - empty stored, new STH tree size > 0 (get all entries error)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to verify STH tree: failed to get all entries: failed to get entries for range[0-3]")
	})

	t.Run("error - empty stored, new STH tree size > max tree size", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{},
			WithMaxTreeSize(1))
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})

	t.Run("error - empty stored, new STH tree size > 0 (STH != merkle tree entries hash)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to verify STH tree: different root hash results from merkle tree building")
	})

	t.Run("error - empty stored, new STH tree size > 0 (get root hash from entries error)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{
			GetRootHashFromEntriesErr: fmt.Errorf("custom get root hash error"),
		}

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to get root hash from entries: custom get root hash error")
	})

	t.Run("success - empty stored, new STH tree size > 0", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		err = store.Activate(testLog)
		require.NoError(t, err)

		logMonitor, err := store.Get(testLog)
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == sthURL {
				return &http.Response{
					Body:       io.NopCloser(bytes.NewBufferString(sth4)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == webfingerURL {
				expected := command.WebFingerResponse{
					Subject: "https://vct.com/maple2021",
					Properties: map[string]interface{}{
						"https://trustbloc.dev/ns/public-key": PublicKey,
					},
					Links: []command.WebFingerLink{{
						Rel:  "self",
						Href: "https://vct.com/maple2021",
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{{
						LeafInput: []byte("leafInput"),
					}},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}), map[string]string{})
		require.NoError(t, err)

		var sthResponse command.GetSTHResponse
		err = json.Unmarshal([]byte(sth4), &sthResponse)
		require.NoError(t, err)

		client.logVerifier = &mockLogVerifier{
			RootHash: sthResponse.SHA256RootHash,
		}

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
	})
}

func TestClient_getEntries(t *testing.T) {
	t.Run("success - paging", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{}, WithMaxGetEntriesRange(2))
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getAllEntries(testLog, vctClient, 4)
		require.NoError(t, err)
		require.Equal(t, 4, len(entries))
	})

	t.Run("success - paging", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{}, WithMaxGetEntriesRange(1))
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getAllEntries(testLog, vctClient, 3)
		require.NoError(t, err)
		require.Equal(t, 3, len(entries))
	})

	t.Run("success - paging with default settings (4 batches)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{})
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		// expecting four batches of 1000 entries (1000-1999,2000-2999,3000-3999, 4000-4073)
		// for test each batch is simulated with one entry
		entries, err := client.getLogEntries(testLog, vctClient, 1000, 4073, true)
		require.NoError(t, err)
		require.Equal(t, 4, len(entries))
	})

	t.Run("success - paging with default settings (one batch)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{})
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getLogEntries(testLog, vctClient, 27, 73, true)
		require.NoError(t, err)
		require.Equal(t, 1, len(entries))
	})

	t.Run("success - paging with default settings (one batch from 1000)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{})
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getLogEntries(testLog, vctClient, 1000, 1073, true)
		require.NoError(t, err)
		require.Equal(t, 1, len(entries))
	})

	t.Run("success - paging with default settings (two batches)", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{})
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getLogEntries(testLog, vctClient, 2973, 4073, true)
		require.NoError(t, err)
		require.Equal(t, 2, len(entries))
	})

	t.Run("success - paging with invalid range", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{})
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getLogEntries(testLog, vctClient, 1000, 500, true)
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "invalid range for get log entries[1000-500]")
	})

	t.Run("error - log entries store error", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, nil, map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithMaxGetEntriesRange(2),
			WithLogEntriesStore(&mockLogEntryStore{StoreErr: fmt.Errorf("store entries error")}))
		require.NoError(t, err)

		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == getEntriesURL {
				expected := command.GetEntriesResponse{
					Entries: []command.LeafEntry{
						{
							LeafInput: []byte("leafInput"),
						},
						{
							LeafInput: []byte("leafInput"),
						},
					},
				}

				fakeResp, e := json.Marshal(expected)
				require.NoError(t, e)

				return &http.Response{
					Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := client.getAllEntries(testLog, vctClient, 2)
		require.Error(t, err)
		require.Empty(t, entries)
		require.Contains(t, err.Error(), "failed to store entries for range[0-1]: store entries error")
	})
}

func TestClient_GetLogEntriesFrom(t *testing.T) {
	t.Run("success ", func(t *testing.T) {
		client, err := New(nil, httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, nil //nolint:nilnil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{GetIter: &mockLogEntryIterator{}}))
		require.NoError(t, err)

		entries, err := client.getStoreEntriesFrom(testLog, 0, 2)
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("error - iterator total items ", func(t *testing.T) {
		client, err := New(nil, httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, nil //nolint:nilnil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{GetIter: &mockLogEntryIterator{
				TotalItemsErr: fmt.Errorf("total items error"),
			}}))
		require.NoError(t, err)

		entries, err := client.getStoreEntriesFrom(testLog, 0, 2)
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "total items error")
	})

	t.Run("error - iterator next ", func(t *testing.T) {
		client, err := New(nil, httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, nil //nolint:nilnil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{
				GetIter: &mockLogEntryIterator{
					ItemCount: 1,
					NextErr:   fmt.Errorf("next error"),
				},
			}))
		require.NoError(t, err)

		entries, err := client.getStoreEntriesFrom(testLog, 0, 2)
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "next error")
	})

	t.Run("error - store error ", func(t *testing.T) {
		client, err := New(nil, httpMock(func(req *http.Request) (*http.Response, error) {
			return nil, nil //nolint:nilnil
		}), map[string]string{},
			WithLogEntriesStoreEnabled(true),
			WithLogEntriesStore(&mockLogEntryStore{GetErr: fmt.Errorf("get entries error")}))
		require.NoError(t, err)

		entries, err := client.getStoreEntriesFrom(testLog, 0, 2)
		require.Error(t, err)
		require.Nil(t, entries)
		require.Contains(t, err.Error(), "get entries error")
	})
}

func TestClient_GetPublicKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			expected := command.WebFingerResponse{
				Subject: "https://vct.com/maple2021",
				Properties: map[string]interface{}{
					"https://trustbloc.dev/ns/public-key": "cHVibGljIGtleQ==",
				},
				Links: []command.WebFingerLink{{
					Rel:  "self",
					Href: "https://vct.com/maple2021",
				}},
			}

			fakeResp, err := json.Marshal(expected)
			require.NoError(t, err)

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
				StatusCode: http.StatusOK,
			}, nil
		})))

		pubKey, err := getPublicKey(vctClient)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
	})

	t.Run("error - public key not a string", func(t *testing.T) {
		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			expected := command.WebFingerResponse{
				Subject: "https://vct.com/maple2021",
				Properties: map[string]interface{}{
					"https://trustbloc.dev/ns/public-key": 123,
				},
				Links: []command.WebFingerLink{{
					Rel:  "self",
					Href: "https://vct.com/maple2021",
				}},
			}

			fakeResp, err := json.Marshal(expected)
			require.NoError(t, err)

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
				StatusCode: http.StatusOK,
			}, nil
		})))

		pubKey, err := getPublicKey(vctClient)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.Contains(t, err.Error(), "public key is not a string")
	})

	t.Run("error - decode public key error", func(t *testing.T) {
		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			expected := command.WebFingerResponse{
				Subject: "https://vct.com/maple2021",
				Properties: map[string]interface{}{
					"https://trustbloc.dev/ns/public-key": "123",
				},
				Links: []command.WebFingerLink{{
					Rel:  "self",
					Href: "https://vct.com/maple2021",
				}},
			}

			fakeResp, err := json.Marshal(expected)
			require.NoError(t, err)

			return &http.Response{
				Body:       io.NopCloser(bytes.NewBuffer(fakeResp)),
				StatusCode: http.StatusOK,
			}, nil
		})))

		pubKey, err := getPublicKey(vctClient)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.Contains(t, err.Error(), "decode public key: illegal base64 data")
	})

	t.Run("error - internal server error", func(t *testing.T) {
		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		pubKey, err := getPublicKey(vctClient)
		require.Error(t, err)
		require.Nil(t, pubKey)
	})

	t.Run("error - no public key", func(t *testing.T) {
		vctClient := vct.New(testLog, vct.WithHTTPClient(httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       io.NopCloser(bytes.NewBuffer([]byte("{}"))),
				StatusCode: http.StatusOK,
			}, nil
		})))

		pubKey, err := getPublicKey(vctClient)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.Contains(t, err.Error(), "no public key")
	})
}

type httpMock func(req *http.Request) (*http.Response, error)

func (m httpMock) Do(req *http.Request) (*http.Response, error) {
	return m(req)
}

type mockLogVerifier struct {
	VerifyConsistencyProofErr error
	GetRootHashFromEntriesErr error

	RootHash []byte
}

func (v *mockLogVerifier) VerifyConsistencyProof(snapshot1, snapshot2 int64, root1, root2 []byte, proof [][]byte) error {
	return v.VerifyConsistencyProofErr
}

func (v *mockLogVerifier) GetRootHashFromEntries(entries []*command.LeafEntry) ([]byte, error) {
	if v.GetRootHashFromEntriesErr != nil {
		return nil, v.GetRootHashFromEntriesErr
	}

	return v.RootHash, nil
}

type mockLogEntryStore struct {
	StoreErr error
	FailErr  error
	GetErr   error

	GetIter *mockLogEntryIterator
}

func (s *mockLogEntryStore) StoreLogEntries(log string, start, end uint64, entries []command.LeafEntry) error {
	return s.StoreErr
}

func (s *mockLogEntryStore) FailLogEntriesFrom(logURL string, start uint64) error {
	return s.FailErr
}

func (s *mockLogEntryStore) GetLogEntriesFrom(logURL string, start uint64) (logentry.EntryIterator, error) {
	if s.GetIter != nil {
		return s.GetIter, nil
	}

	return &mockLogEntryIterator{}, s.GetErr
}

type mockLogEntryIterator struct {
	TotalItemsErr error
	NextErr       error

	ItemCount int
}

func (e *mockLogEntryIterator) TotalItems() (int, error) {
	if e.TotalItemsErr != nil {
		return 0, e.TotalItemsErr
	}

	return e.ItemCount, nil
}

func (e *mockLogEntryIterator) Next() (*command.LeafEntry, error) {
	if e.NextErr != nil {
		return nil, e.NextErr
	}

	return nil, nil //nolint:nilnil
}

func (e *mockLogEntryIterator) Close() error {
	return nil
}

var storedEntries = []command.LeafEntry{
	{
		LeafInput: []byte("leafInput-0"),
	},
	{
		LeafInput: []byte("leafInput-1"),
	},
	{
		LeafInput: []byte("leafInput-2"),
	},
	{
		LeafInput: []byte("leafInput-3"),
	},
	{
		LeafInput: []byte("leafInput-4"),
	},
}

var sth0 = `{
  "tree_size": 0,
  "timestamp": 1662493474864,
  "sha256_root_hash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsic2lnbmF0dXJlIjoiRUNEU0EiLCJ0eXBlIjoiRUNEU0FQMjU2REVSIn0sInNpZ25hdHVyZSI6Ik1FUUNJRnVneG8wSVZuZjh2K2Y2MG0rUUpVV3dKRU9tZ0IzMmoyVm9SRWFHWmJCdEFpQXZmRFRUSERwVG04bXJxZHdFRGFBZmRvMUhPU3dDRUpvNVBNaG1pbEFHU1E9PSJ9"
}`

var sth4 = `{
  "tree_size": 4,
  "timestamp": 1662493604367,
  "sha256_root_hash": "ERzuJAV+f4ul44vU0dxxS6nWr8yzb1CZu3JClS7aAIk=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsic2lnbmF0dXJlIjoiRUNEU0EiLCJ0eXBlIjoiRUNEU0FQMjU2REVSIn0sInNpZ25hdHVyZSI6Ik1FVUNJRmtrRkFTZUlWNWsxZzBrSzdONE80MEM5Ni9ITk9HTDV0Y0EvK0pRRVFMcEFpRUF3QWpsWFlmV3ZiZk90ajQxY1JoS29qeDkyZ29jMER5aXRleVVROVRIeEdzPSJ9"
}`

var sth5 = `{
  "tree_size": 5,
  "timestamp": 1662493614262,
  "sha256_root_hash": "WYRAkV3WzAAmg9jwnWhJyrA2+3BF4whEzi9BljqrcQY=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsic2lnbmF0dXJlIjoiRUNEU0EiLCJ0eXBlIjoiRUNEU0FQMjU2REVSIn0sInNpZ25hdHVyZSI6Ik1FVUNJRUZxMHNxNmN0ZUtUZmZKbzlMbmZua3pKS2Qxb3Z5cDNuMHZFZ05qdGQxMUFpRUFrQTZJQ1VMU1dRRGw4YTFsdkE0c29xQ3NnY1JnNEh5bE1PMDdYWGh1a21VPSJ9"
}`

const (
	PublicKey          = `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2Di7Fea52hG12mc6VVhHIlbC/F2KMgh2fs6bweeHojWBCxzKoLya5ty4ZmjM5agWMyTBvfrJ4leWAlCoCV2yvA==`
	DifferentPublicKey = `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYH7+MO+X0YPnGkvK1Nmy/4/r9HpgPPku9gjw3k3zOl+PTbu7iEL2gsiH/KHaFbeMoMcj5Tv0OkA/EKfuzd0imQ==`
)
