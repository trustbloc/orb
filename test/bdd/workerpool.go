/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"sync"
)

// Request is a request that's submitted to the worker pool for processing
type Request[T any] interface {
	Invoke() (T, error)
	URL() string
}

// Response is the response for an individual request
type Response[T any] struct {
	Request[T]
	Resp T
	Err  error
}

// WorkerPool manages a pool of workers that processes requests concurrently and, at the end, gathers the responses
type WorkerPool[T any] struct {
	*workerPoolOptions

	workers   []*worker[T]
	reqChan   chan Request[T]
	respChan  chan *Response[T]
	wgResp    sync.WaitGroup
	wg        *sync.WaitGroup
	responses []*Response[T]
}

type workerPoolOptions struct {
	taskDescription string
}

type Opt func(*workerPoolOptions)

func WithTaskDescription(desc string) Opt {
	return func(options *workerPoolOptions) {
		options.taskDescription = desc
	}
}

// NewWorkerPool returns a new worker pool with the given number of workers
func NewWorkerPool[T any](num int, opts ...Opt) *WorkerPool[T] {
	options := &workerPoolOptions{}

	for _, opt := range opts {
		opt(options)
	}

	reqChan := make(chan Request[T])
	respChan := make(chan *Response[T])
	workers := make([]*worker[T], num)

	wg := &sync.WaitGroup{}

	for i := 0; i < num; i++ {
		workers[i] = newWorker[T](reqChan, respChan, wg)
	}

	return &WorkerPool[T]{
		workerPoolOptions: options,
		workers:           workers,
		reqChan:           reqChan,
		respChan:          respChan,
		wg:                wg,
	}
}

// Start starts all of the workers and listens for responses
func (p *WorkerPool[T]) Start() {
	p.wgResp.Add(1)

	go p.listen()

	p.wg.Add(len(p.workers))

	for _, w := range p.workers {
		go w.start()
	}
}

// Stop stops the workers in the pool and stops listening for responses
func (p *WorkerPool[T]) Stop() {
	close(p.reqChan)

	logger.Infof("Waiting %d for workers to finish...", len(p.workers))

	p.wg.Wait()

	logger.Infof("... all %d workers finished.", len(p.workers))

	close(p.respChan)

	logger.Infof("Waiting for listener to finish...")

	p.wgResp.Wait()

	logger.Infof("... listener finished.")
}

// Submit submits a request for processing
func (p *WorkerPool[T]) Submit(req Request[T]) {
	p.reqChan <- req
}

// Responses contains the responses after the pool is stopped
func (p *WorkerPool[T]) Responses() []*Response[T] {
	return p.responses
}

func (p *WorkerPool[T]) listen() {
	for resp := range p.respChan {
		p.responses = append(p.responses, resp)

		if len(p.responses)%100 == 0 {
			if p.taskDescription != "" {
				logger.Debugf("Got %d responses for task [%s]", len(p.responses), p.taskDescription)
			} else {
				logger.Debugf("Got %d responses", len(p.responses))
			}
		}
	}

	logger.Info("Exiting listener")

	p.wgResp.Done()
}

type worker[T any] struct {
	reqChan  chan Request[T]
	respChan chan *Response[T]
	wg       *sync.WaitGroup
}

func newWorker[T any](reqChan chan Request[T], respChan chan *Response[T], wg *sync.WaitGroup) *worker[T] {
	return &worker[T]{
		reqChan:  reqChan,
		respChan: respChan,
		wg:       wg,
	}
}

func (w *worker[T]) start() {
	for req := range w.reqChan {
		data, err := req.Invoke()
		w.respChan <- &Response[T]{
			Request: req,
			Resp:    data,
			Err:     err,
		}
	}

	w.wg.Done()
}
