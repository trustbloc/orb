/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/trustbloc/orb/pkg/activitypub/service/activityhandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/inbox"
	"github.com/trustbloc/orb/pkg/activitypub/service/lifecycle"
	"github.com/trustbloc/orb/pkg/activitypub/service/mempubsub"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox/redelivery"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

const activitiesTopic = "activities"

// PubSub defines the functions for a publisher/subscriber.
type PubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// PubSubFactory creates a publisher/subscriber.
type PubSubFactory func(serviceName string) PubSub

// Config holds the configuration parameters for an ActivityPub service.
type Config struct {
	ServiceName               string
	ListenAddress             string
	ServiceIRI                *url.URL
	RetryOpts                 *redelivery.Config
	PubSubFactory             PubSubFactory
	ActivityHandlerBufferSize int
}

// Service implements an ActivityPub service which has an inbox, outbox, and
// handlers for the various ActivityPub activities.
type Service struct {
	*lifecycle.Lifecycle

	inbox           *inbox.Inbox
	outbox          *outbox.Outbox
	activityHandler spi.ActivityHandler
}

// NewService returns a new ActivityPub service.
func NewService(cfg *Config, activityStore store.Store, handlerOpts ...spi.HandlerOpt) (*Service, error) {
	ob, err := outbox.New(
		&outbox.Config{
			ServiceName:      cfg.ServiceName,
			Topic:            activitiesTopic,
			RedeliveryConfig: cfg.RetryOpts,
		},
		activityStore, newPubSub(cfg, "outbox-"+cfg.ServiceName),
		handlerOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("create outbox failed: %w", err)
	}

	handler := activityhandler.New(
		&activityhandler.Config{
			ServiceName: cfg.ServiceName,
			BufferSize:  cfg.ActivityHandlerBufferSize,
			ServiceIRI:  cfg.ServiceIRI,
		},
		activityStore, ob, handlerOpts...)

	ib, err := inbox.New(
		&inbox.Config{
			ServiceName:   cfg.ServiceName,
			Topic:         activitiesTopic,
			ListenAddress: cfg.ListenAddress,
		},
		activityStore,
		newPubSub(cfg, "inbox-"+cfg.ServiceName),
		handler,
	)
	if err != nil {
		return nil, fmt.Errorf("create inbox failed: %w", err)
	}

	s := &Service{
		inbox:           ib,
		outbox:          ob,
		activityHandler: handler,
	}

	s.Lifecycle = lifecycle.New(cfg.ServiceName,
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop),
	)

	return s, nil
}

func (s *Service) start() {
	s.activityHandler.Start()
	s.inbox.Start()
	s.outbox.Start()
}

func (s *Service) stop() {
	s.outbox.Stop()
	s.inbox.Stop()
	s.activityHandler.Stop()
}

// Outbox returns the outbox, which allows clients to post activities.
func (s *Service) Outbox() spi.Outbox {
	return s.outbox
}

// Subscribe allows a client to receive published activities.
func (s *Service) Subscribe() <-chan *vocab.ActivityType {
	return s.activityHandler.Subscribe()
}

func newPubSub(cfg *Config, serviceName string) PubSub {
	if cfg.PubSubFactory != nil {
		return cfg.PubSubFactory(serviceName)
	}

	return mempubsub.New(serviceName, mempubsub.DefaultConfig())
}
