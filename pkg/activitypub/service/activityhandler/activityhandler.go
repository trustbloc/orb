/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package activityhandler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/trustbloc/logutil-go/pkg/log"

	logfields "github.com/trustbloc/orb/internal/pkg/log"
	service "github.com/trustbloc/orb/pkg/activitypub/service/spi"
	store "github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/lifecycle"
)

const (
	loggerModule = "activitypub_service"

	defaultBufferSize      = 100
	defaultMaxWitnessDelay = 10 * time.Minute
)

// Config holds the configuration parameters for the activity handler.
type Config struct {
	// ServiceName is the name of the service (used for logging).
	ServiceName string

	// ServiceIRI is the IRI of the local service (actor). It is used as the 'actor' in activities
	// that are posted to the outbox by the handler. This IRI may be an HTTP(s) address or a DID.
	ServiceIRI *url.URL

	// ServiceEndpointURL is the HTTP(s) endpoint of the service (actor).
	ServiceEndpointURL *url.URL

	// BufferSize is the size of the Go channel buffer for a subscription.
	BufferSize int

	// MaxWitnessDelay is the maximum delay from when the witness receives the transaction (via an Offer) for
	// the witness to include the transaction into the ledger.
	MaxWitnessDelay time.Duration
}

type activityPubClient interface {
	GetActor(iri *url.URL) (*vocab.ActorType, error)
}

type undoFunc func(activity *vocab.ActivityType) error

type handler struct {
	*Config
	*lifecycle.Lifecycle

	store             store.Store
	mutex             sync.RWMutex
	subscribers       []chan *vocab.ActivityType
	client            activityPubClient
	undoFollow        undoFunc
	undoInviteWitness undoFunc
	undoLike          undoFunc
	logger            *log.Log
}

func newHandler(cfg *Config, s store.Store, activityPubClient activityPubClient,
	undoFollow, undoInviteWitness, undoLike undoFunc) *handler {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = defaultBufferSize
	}

	if cfg.MaxWitnessDelay == 0 {
		cfg.MaxWitnessDelay = defaultMaxWitnessDelay
	}

	h := &handler{
		Config:            cfg,
		store:             s,
		client:            activityPubClient,
		undoFollow:        undoFollow,
		undoInviteWitness: undoInviteWitness,
		undoLike:          undoLike,
		logger:            log.New(loggerModule, log.WithFields(logfields.WithServiceName(cfg.ServiceName))),
	}

	h.Lifecycle = lifecycle.New(cfg.ServiceName, lifecycle.WithStop(h.stop))

	return h
}

func (h *handler) stop() {
	h.logger.Info("Stopping activity handler")

	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, ch := range h.subscribers {
		close(ch)
	}

	h.subscribers = nil
}

// Subscribe allows a client to receive published activities.
func (h *handler) Subscribe() <-chan *vocab.ActivityType {
	ch := make(chan *vocab.ActivityType, h.BufferSize)

	h.mutex.Lock()
	h.subscribers = append(h.subscribers, ch)
	h.mutex.Unlock()

	return ch
}

func (h *handler) handleUndoActivity(_ context.Context, undo *vocab.ActivityType) error {
	h.logger.Debug("Handling 'Undo' activity", logfields.WithActivityID(undo.ID()))

	if undo.Actor() == nil {
		return orberrors.NewBadRequest(fmt.Errorf("no actor specified in 'Undo' activity"))
	}

	activityInUndo := undo.Object().Activity()
	if activityInUndo == nil || activityInUndo.ID() == nil {
		return orberrors.NewBadRequest(fmt.Errorf("no activity specified in 'object' field of the 'Undo' activity"))
	}

	activity, err := h.store.GetActivity(activityInUndo.ID().URL())
	if err != nil {
		e := fmt.Errorf("unable to retrieve activity %s from storage: %w", activityInUndo.ID().URL(), err)

		if errors.Is(err, store.ErrNotFound) {
			return e
		}

		return orberrors.NewTransient(e)
	}

	if activity.Actor() == nil {
		// This shouldn't happen since the activity was validated before it was stored.
		return fmt.Errorf("no actor in stored '%s' activity: %s", activity.Type(), activity.ID())
	}

	if activity.Actor().String() != undo.Actor().String() {
		return orberrors.NewBadRequest(
			fmt.Errorf("not handling 'Undo' activity %s since the actor of the 'Undo' [%s] is not"+
				" the same as the actor of the original activity [%s]", undo.ID(), undo.Actor(), activity.Actor()))
	}

	err = validateActivityInUndo(activityInUndo, activity)
	if err != nil {
		return fmt.Errorf("invalid activity in Undo [%s]: %w", undo.ID(), err)
	}

	err = h.undoActivity(activity)
	if err != nil {
		return fmt.Errorf("undo activity [%s]: %w", undo.ID(), err)
	}

	h.notify(undo)

	return nil
}

func (h *handler) undoActivity(activity *vocab.ActivityType) error {
	switch {
	case activity.Type().Is(vocab.TypeFollow):
		return h.undoFollow(activity)

	case activity.Type().Is(vocab.TypeInvite):
		return h.undoInviteWitness(activity)

	case activity.Type().Is(vocab.TypeLike):
		return h.undoLike(activity)

	default:
		return fmt.Errorf("undo of type %s is not supported", activity.Type())
	}
}

func (h *handler) notify(activity *vocab.ActivityType) {
	h.mutex.RLock()
	subscribers := h.subscribers
	h.mutex.RUnlock()

	for _, ch := range subscribers {
		ch <- activity
	}
}

func defaultOptions() *service.Handlers {
	return &service.Handlers{
		AnchorHandler:         &noOpAnchorCredentialPublisher{},
		FollowerAuth:          &AcceptAllActorsAuth{},
		WitnessInvitationAuth: &AcceptAllActorsAuth{},
		ProofHandler:          &noOpProofHandler{},
		AnchorAckHandler:      &noOpAnchorAcknowledgementHandler{},
	}
}

func containsIRI(iris []*url.URL, iri fmt.Stringer) bool {
	for _, f := range iris {
		if f.String() == iri.String() {
			return true
		}
	}

	return false
}

func validateActivityInUndo(activityInUndo, activity *vocab.ActivityType) error {
	if !activityInUndo.Type().Is(activity.Type().Types()...) {
		return orberrors.NewBadRequestf("invalid type - expecting %s but got %s", activity.Type(), activityInUndo.Type())
	}

	if activity.Object().IRI() != nil {
		if err := validateObjectIRIInUndo(activityInUndo, activity); err != nil {
			return err
		}
	} else if anchorEvent := activity.Object().AnchorEvent(); anchorEvent != nil {
		if err := validateAnchorEventInUndo(activityInUndo.Object().AnchorEvent(), anchorEvent); err != nil {
			return err
		}
	}

	if activity.Target().IRI() != nil {
		if err := validateTargetInUndo(activityInUndo.Target(), activity.Target()); err != nil {
			return err
		}
	}

	return nil
}

func validateObjectIRIInUndo(activityInUndo, activity *vocab.ActivityType) error {
	if activityInUndo.Object().IRI() == nil {
		return orberrors.NewBadRequestf("nil object IRI - expecting %s", activity.Object().IRI())
	}

	if activityInUndo.Object().IRI().String() != activity.Object().IRI().String() {
		return orberrors.NewBadRequestf("object IRI mismatch - expecting %s but got %s",
			activity.Object().IRI(), activityInUndo.Object().IRI())
	}

	return nil
}

func validateAnchorEventInUndo(anchorEventInUndo, anchorEvent *vocab.AnchorEventType) error {
	if anchorEventInUndo == nil || len(anchorEvent.URL()) > 0 && !anchorEventInUndo.URL().Equals(anchorEvent.URL()) {
		return orberrors.NewBadRequestf("invalid anchor event URL %s - expecting %s",
			anchorEventInUndo.URL(), anchorEvent.URL())
	}

	return nil
}

func validateTargetInUndo(targetInUndo, target *vocab.ObjectProperty) error {
	if targetInUndo.IRI() == nil {
		return orberrors.NewBadRequestf("nil target IRI - expecting %s", target.IRI())
	}

	if targetInUndo.IRI().String() != target.IRI().String() {
		return orberrors.NewBadRequestf("target IRI mismatch - expecting %s but got %s",
			target.IRI(), targetInUndo.IRI())
	}

	return nil
}
