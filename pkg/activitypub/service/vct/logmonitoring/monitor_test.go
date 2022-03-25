/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package logmonitoring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/pkg/store/logmonitor"
	storemocks "github.com/trustbloc/orb/pkg/store/mocks"
)

const (
	testLog = "vct.com"

	sthURL        = "vct.com/v1/get-sth"
	getEntriesURL = "vct.com/v1/get-entries"
	webfingerURL  = "vct.com/.well-known/webfinger"
)

func TestNew(t *testing.T) {
	store, err := logmonitor.New(mem.NewProvider())
	require.NoError(t, err)

	client, err := New(store, nil)
	require.NoError(t, err)
	require.NotNil(t, client)
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
		require.NoError(t, err)

		client.MonitorLogs()
	})

	t.Run("success - no active logs found", func(t *testing.T) {
		store, err := logmonitor.New(mem.NewProvider())
		require.NoError(t, err)

		client, err := New(store, httpMock(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
		require.NoError(t, err)

		client.processLog(&logmonitor.LogMonitor{Log: testLog})
	})
}

// nolint:gocognit,gocyclo,cyclop
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth4)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.NoError(t, err)
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
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == "vct.com/v1/get-sth-consistency" {
				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString("{}")),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth5)),
					StatusCode: http.StatusOK,
				}, nil
			}

			if req.URL.Path == "vct.com/v1/get-sth-consistency" {
				return &http.Response{
					Body:       ioutil.NopCloser(bytes.NewBufferString("{}")),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth0)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth4)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to verify STH tree: failed to get all entries: failed to get entries for range[0-3]")
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
					Body:       ioutil.NopCloser(bytes.NewBufferString(sth4)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		}))
		require.NoError(t, err)

		err = client.checkVCTConsistency(logMonitor)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"failed to verify STH tree: different root hash results from merkle tree building")
	})
}

func TestClient_getEntries(t *testing.T) {
	t.Run("success - paging", func(t *testing.T) {
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := getEntries(testLog, vctClient, 4, 2)
		require.NoError(t, err)
		require.Equal(t, 4, len(entries))
	})

	t.Run("success - paging", func(t *testing.T) {
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
					Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
					StatusCode: http.StatusOK,
				}, nil
			}

			return &http.Response{
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
				StatusCode: http.StatusInternalServerError,
			}, nil
		})))

		entries, err := getEntries(testLog, vctClient, 3, 1)
		require.NoError(t, err)
		require.Equal(t, 3, len(entries))
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
				Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
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
				Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
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
				Body:       ioutil.NopCloser(bytes.NewBuffer(fakeResp)),
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
				Body:       ioutil.NopCloser(bytes.NewBufferString(`{}`)),
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
				Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("{}"))),
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

//nolint:lll
var sth0 = `{
  "tree_size": 0,
  "timestamp": 1647375563852,
  "sha256_root_hash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiIySWhVNzUwQlkxWG5tY1A4OHlONlViZG1NaEhLMjdORWxHU0l0V2ZoNFV4Z2Z3WWhXTm8yYVVSSjk2Q3JsOWs3T09Ddm9zamxtME9rR2kwTjlVODJ5UT09In0="
}`

//nolint:lll
var sth4 = `{
  "tree_size": 4,
  "timestamp": 1647375715221,
  "sha256_root_hash": "GNW0EPlQ+QoKh76QtVqlM3HazFNndRLMolw3P4Ag510=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiIyWVh4NHZxalZhSTdFMGhKdnhldW1mYXBwRU9RZWU2Qm51Wmc0WmNXM2JqdlF6ZGd5bmtsVVNZYm9DbFkreDNiRXFXSXlGdEtVaE9UUjMxckpwbXpDdz09In0="
}`

//nolint:lll
var sth5 = `{
  "tree_size": 5,
  "timestamp": 1647375720248,
  "sha256_root_hash": "F662myG5fHA2ASVuWBfBLWxGZWgLz1LaB0Cl1GDKGOg=",
  "tree_head_signature": "eyJhbGdvcml0aG0iOnsiaGFzaCI6IlNIQTI1NiIsInNpZ25hdHVyZSI6IkVDRFNBIiwidHlwZSI6IkVDRFNBUDI1NklFRUVQMTM2MyJ9LCJzaWduYXR1cmUiOiJtSGVlUXRpNTh4UjZCcXFYWEtPekgwcW51N3RnckgwQ0NGRC9hT0F5WWdYU3IvdkttMHg5RDRpZFNXTElDeTJybEt1UVpmaUNPd3pTeDgxR0N3Wm5uQT09In0="
}`

const (
	PublicKey          = `BJCTYDUeK7Z9COucTLYMcP1k5Olf524eJ8cxeXps6OovEUl2PBGVBT//pVtwgLQWp4FdupFXp9mMd5flDK6C3/Q=`
	DifferentPublicKey = `BE8R63bF0Qasqj/j+vwz/s/X9Ofdi1Ts2ShTnAQbzuDzA+S0mOyR9wzthyh3+1Ynpo1/izm6wy75/SrX01U+kEA=`
)
