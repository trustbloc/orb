/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
)

var logger = log.New("activitypub_resthandler")

const (
	// FollowersPath specifies the service's 'followers' endpoint.
	FollowersPath = "/followers"
	// FollowingPath specifies the service's 'following' endpoint.
	FollowingPath = "/following"
	// OutboxPath specifies the service's 'outbox' endpoint.
	OutboxPath = "/outbox"
	// InboxPath specifies the service's 'inbox' endpoint.
	InboxPath = "/inbox"
)

const (
	pageParam    = "page"
	pageNumParam = "page-num"
)

// Config contains configuration parameters for the handler.
type Config struct {
	BasePath   string
	ServiceIRI *url.URL
	PageSize   int
}

type handler struct {
	*Config

	id            string
	endpoint      string
	params        map[string]string
	activityStore spi.Store
	handler       common.HTTPRequestHandler
	marshal       func(v interface{}) ([]byte, error)
	writeResponse func(w http.ResponseWriter, status int, body []byte)
	getParams     func(req *http.Request) map[string][]string
}

func newHandler(endpoint string, cfg *Config, s spi.Store, h common.HTTPRequestHandler, params ...string) *handler {
	id := fmt.Sprintf("%s%s", cfg.ServiceIRI, endpoint)

	return &handler{
		Config:        cfg,
		id:            id,
		endpoint:      fmt.Sprintf("%s%s", cfg.BasePath, endpoint),
		params:        paramsBuilder(params).build(),
		activityStore: s,
		handler:       h,
		marshal:       json.Marshal,
		getParams: func(req *http.Request) map[string][]string {
			return req.URL.Query()
		},
		writeResponse: func(w http.ResponseWriter, status int, body []byte) {
			if len(body) > 0 {
				if _, err := w.Write(body); err != nil {
					logger.Warnf("[%s] Unable to write response: %s", endpoint, err)

					return
				}

				logger.Debugf("[%s] Wrote response: %s", endpoint, body)
			}

			w.WriteHeader(status)
		},
	}
}

// Path returns the base path of the target URL for this handler.
func (h *handler) Path() string {
	return h.endpoint
}

// Params returns the accepted parameters.
func (h *handler) Params() map[string]string {
	return h.params
}

// Method returns the HTTP method, which is always GET.
func (h *handler) Method() string {
	return http.MethodGet
}

// Handler returns the handler that should be invoked when an HTTP GET is requested to the target endpoint.
// This handler must be registered with an HTTP server.
func (h *handler) Handler() common.HTTPRequestHandler {
	return h.handler
}

func (h *handler) getPageID(pageNum int) string {
	if pageNum >= 0 {
		return fmt.Sprintf("%s?%s=true&%s=%d", h.id, pageParam, pageNumParam, pageNum)
	}

	return fmt.Sprintf("%s?%s=true", h.id, pageParam)
}

func (h *handler) getPageURL(pageNum int) (*url.URL, error) {
	pageID := h.getPageID(pageNum)

	pageURL, err := url.Parse(pageID)
	if err != nil {
		return nil, fmt.Errorf("invalid 'page' URL [%s]: %w", pageID, err)
	}

	return pageURL, nil
}

func (h *handler) getCurrentPrevNext(totalItems int, options *spi.QueryOptions) (int, int, int) {
	first := getFirstPageNum(totalItems, options.PageSize, options.SortOrder)
	last := getLastPageNum(totalItems, options.PageSize, options.SortOrder)

	var current int
	if options.PageNumber >= 0 {
		current = options.PageNumber
	} else {
		current = first
	}

	var prev, next int

	if options.SortOrder == spi.SortDescending {
		prev, next = getPrevNextDescending(current, first, last)
	} else {
		prev, next = getPrevNextAscending(current, first, last)
	}

	return current, prev, next
}

func (h *handler) getIDPrevNextURL(totalItems int, options *spi.QueryOptions) (string, *url.URL, *url.URL, error) {
	current, prev, next := h.getCurrentPrevNext(totalItems, options)

	var err error

	var nextURL *url.URL

	var prevURL *url.URL

	if prev >= 0 {
		prevURL, err = h.getPageURL(prev)
		if err != nil {
			return "", nil, nil, err
		}
	}

	if next >= 0 {
		nextURL, err = h.getPageURL(next)
		if err != nil {
			return "", nil, nil, err
		}
	}

	return h.getPageID(current), prevURL, nextURL, nil
}

func (h *handler) isPaging(req *http.Request) bool {
	return h.paramAsBool(req, pageParam)
}

func (h *handler) getPageNum(req *http.Request) (int, bool) {
	return h.paramAsInt(req, pageNumParam)
}

func (h *handler) paramAsInt(req *http.Request, param string) (int, bool) {
	params := h.getParams(req)

	values := params[param]
	if len(values) == 0 || values[0] == "" {
		return 0, false
	}

	size, err := strconv.Atoi(values[0])
	if err != nil {
		logger.Debugf("Invalid value for parameter [%s]: %s", param, err)

		return 0, false
	}

	return size, true
}

func (h *handler) paramAsBool(req *http.Request, param string) bool {
	params := h.getParams(req)

	values := params[param]
	if len(values) == 0 || values[0] == "" {
		return false
	}

	b, err := strconv.ParseBool(values[0])
	if err != nil {
		logger.Debugf("Invalid value for parameter [%s]: %s", param, err)

		return false
	}

	return b
}

func getPrevNextAscending(current, first, last int) (int, int) {
	prev := -1
	next := -1

	if current < last {
		next = current + 1
	}

	if current > first {
		if current > last {
			prev = last
		} else {
			prev = current - 1
		}
	}

	return prev, next
}

func getPrevNextDescending(current, first, last int) (int, int) {
	prev := -1
	next := -1

	if current > last {
		if current > first {
			next = first
		} else {
			next = current - 1
		}
	}

	if current < first {
		prev = current + 1
	}

	return prev, next
}

func getFirstPageNum(totalItems, pageSize int, sortOrder spi.SortOrder) int {
	if sortOrder == spi.SortAscending {
		return 0
	}

	if totalItems%pageSize > 0 {
		return totalItems / pageSize
	}

	return totalItems/pageSize - 1
}

func getLastPageNum(totalItems, pageSize int, sortOrder spi.SortOrder) int {
	if sortOrder == spi.SortDescending {
		return 0
	}

	if totalItems%pageSize > 0 {
		return totalItems / pageSize
	}

	return totalItems/pageSize - 1
}

type paramsBuilder []string

func (p paramsBuilder) build() map[string]string {
	m := make(map[string]string)

	for _, p := range p {
		m[p] = fmt.Sprintf("{%s}", p)
	}

	return m
}
