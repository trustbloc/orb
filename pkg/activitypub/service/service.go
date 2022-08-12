/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/common"

	"github.com/trustbloc/orb/pkg/activitypub/client"
	"github.com/trustbloc/orb/pkg/activitypub/client/transport"
	"github.com/trustbloc/orb/pkg/activitypub/resthandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/activityhandler"
	"github.com/trustbloc/orb/pkg/activitypub/service/inbox"
	"github.com/trustbloc/orb/pkg/activitypub/service/outbox"
	"github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/lifecycle"
	pubsub "github.com/trustbloc/orb/pkg/pubsub/spi"
)

const (
	inboxActivitiesTopic  = "orb.activity.inbox"
	outboxActivitiesTopic = "orb.activity.outbox"
)

// PubSub defines the functions for a publisher/subscriber.
type PubSub interface {
	Subscribe(ctx context.Context, topic string) (<-chan *message.Message, error)
	SubscribeWithOpts(ctx context.Context, topic string, opts ...pubsub.Option) (<-chan *message.Message, error)
	Publish(topic string, messages ...*message.Message) error
	Close() error
}

// Config holds the configuration parameters for an ActivityPub service.
type Config struct {
	ServicePath               string
	ServiceIRI                *url.URL
	ServiceEndpointURL        *url.URL
	ActivityHandlerBufferSize int
	VerifyActorInSignature    bool

	// MaxWitnessDelay is the maximum delay that the witnessed transaction becomes included into the ledger.
	MaxWitnessDelay time.Duration

	IRICacheSize             int
	IRICacheExpiration       time.Duration
	OutboxSubscriberPoolSize int
	InboxSubscriberPoolSize  int
}

// Service implements an ActivityPub service which has an inbox, outbox, and
// handlers for the various ActivityPub activities.
type Service struct {
	*lifecycle.Lifecycle

	inbox           *inbox.Inbox
	outbox          *outbox.Outbox
	activityHandler *activityhandler.Inbox
}

type httpTransport interface {
	Post(ctx context.Context, req *transport.Request, payload []byte) (*http.Response, error)
	Get(ctx context.Context, req *transport.Request) (*http.Response, error)
}

type signatureVerifier interface {
	VerifyRequest(req *http.Request) (bool, *url.URL, error)
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
	GetReferences(iri *url.URL) (client.ReferenceIterator, error)
	GetActivities(iri *url.URL, order client.Order) (client.ActivityIterator, error)
}

type resourceResolver interface {
	ResolveHostMetaLink(uri, linkType string) (string, error)
}

type authTokenManager interface {
	RequiredAuthTokens(endpoint, method string) ([]string, error)
}

type metricsProvider interface {
	InboxHandlerTime(activityType string, value time.Duration)
	OutboxPostTime(value time.Duration)
	OutboxResolveInboxesTime(value time.Duration)
	OutboxIncrementActivityCount(activityType string)
}

// New returns a new ActivityPub service.
//nolint:funlen
func New(cfg *Config, activityStore store.Store, t httpTransport, sigVerifier signatureVerifier,
	pubSub PubSub, activityPubClient activityPubClient, resourceResolver resourceResolver,
	tm authTokenManager, m metricsProvider, handlerOpts ...spi.HandlerOpt) (*Service, error) {
	outboxHandler := activityhandler.NewOutbox(
		&activityhandler.Config{
			ServiceName:        cfg.ServicePath + resthandler.OutboxPath,
			BufferSize:         cfg.ActivityHandlerBufferSize,
			ServiceIRI:         cfg.ServiceIRI,
			ServiceEndpointURL: cfg.ServiceEndpointURL,
		},
		activityStore, activityPubClient)

	ob, err := outbox.New(
		&outbox.Config{
			ServiceName:        cfg.ServicePath,
			ServiceIRI:         cfg.ServiceIRI,
			ServiceEndpointURL: cfg.ServiceEndpointURL,
			Topic:              outboxActivitiesTopic,
			CacheSize:          cfg.IRICacheSize,
			CacheExpiration:    cfg.IRICacheExpiration,
			SubscriberPoolSize: cfg.OutboxSubscriberPoolSize,
		},
		activityStore, pubSub,
		t, outboxHandler, activityPubClient, resourceResolver, m,
	)
	if err != nil {
		return nil, fmt.Errorf("create outbox failed: %w", err)
	}

	inboxHandler := activityhandler.NewInbox(
		&activityhandler.Config{
			ServiceName:        cfg.ServicePath + resthandler.InboxPath,
			BufferSize:         cfg.ActivityHandlerBufferSize,
			ServiceIRI:         cfg.ServiceIRI,
			ServiceEndpointURL: cfg.ServiceEndpointURL,
			MaxWitnessDelay:    cfg.MaxWitnessDelay,
		},
		activityStore, ob, activityPubClient, handlerOpts...)

	ib, err := inbox.New(
		&inbox.Config{
			ServiceEndpoint:        cfg.ServicePath + resthandler.InboxPath,
			ServiceIRI:             cfg.ServiceIRI,
			Topic:                  inboxActivitiesTopic,
			VerifyActorInSignature: cfg.VerifyActorInSignature,
			SubscriberPoolSize:     cfg.InboxSubscriberPoolSize,
		},
		activityStore, pubSub,
		inboxHandler, sigVerifier, tm, m,
	)
	if err != nil {
		return nil, fmt.Errorf("create inbox failed: %w", err)
	}

	s := &Service{
		inbox:           ib,
		outbox:          ob,
		activityHandler: inboxHandler,
	}

	s.Lifecycle = lifecycle.New(cfg.ServicePath,
		lifecycle.WithStart(s.start),
		lifecycle.WithStop(s.stop),
	)

	return s, nil
}

func (s *Service) start() {
	s.activityHandler.Start()
	s.outbox.Start()
	s.inbox.Start()
}

func (s *Service) stop() {
	s.inbox.Stop()
	s.outbox.Stop()
	s.activityHandler.Stop()
}

// Outbox returns the outbox, which allows clients to post activities.
func (s *Service) Outbox() spi.Outbox {
	return s.outbox
}

// InboxHandler returns the handler for inbox activities.
func (s *Service) InboxHandler() spi.InboxHandler {
	return s.activityHandler
}

// InboxHTTPHandler returns the HTTP handler for the inbox which is invoked by the HTTP server.
// This handler must be registered with an HTTP server.
func (s *Service) InboxHTTPHandler() common.HTTPHandler {
	return s.inbox.HTTPHandler()
}

// Subscribe allows a client to receive published activities.
func (s *Service) Subscribe() <-chan *vocab.ActivityType {
	return s.activityHandler.Subscribe()
}
