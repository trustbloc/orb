/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// ActivityType defines an 'activity'.
type ActivityType struct {
	*ObjectType

	activity *activityType
}

type activityType struct {
	Actor  *URLProperty    `json:"actor,omitempty"`
	Target *ObjectProperty `json:"target,omitempty"`
	Object *ObjectProperty `json:"object,omitempty"`
	Result *ObjectProperty `json:"result,omitempty"`
}

// Actor returns the actor for the activity.
func (t *ActivityType) Actor() *url.URL {
	if t == nil || t.activity == nil || t.activity.Actor == nil {
		return nil
	}

	return t.activity.Actor.URL()
}

// SetActor sets the actor for the activity.
func (t *ActivityType) SetActor(iri *url.URL) {
	t.activity.Actor = NewURLProperty(iri)
}

// Target returns the target of the activity.
func (t *ActivityType) Target() *ObjectProperty {
	if t == nil || t.activity == nil {
		return nil
	}

	return t.activity.Target
}

// Object returns the object of the activity.
func (t *ActivityType) Object() *ObjectProperty {
	if t == nil || t.activity == nil {
		return nil
	}

	return t.activity.Object
}

// Result returns the result.
func (t *ActivityType) Result() *ObjectProperty {
	if t == nil || t.activity == nil {
		return nil
	}

	return t.activity.Result
}

// MarshalJSON marshals the activity.
func (t *ActivityType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.activity)
}

// UnmarshalJSON unmarshals the activity.
func (t *ActivityType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.activity = &activityType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.activity)
}

// NewCreateActivity returns a new 'Create' activity.
func NewCreateActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeCreate),
			WithTo(options.To...),
			WithPublishedTime(options.Published),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Target: options.Target,
			Object: obj,
		},
	}
}

// NewAnnounceActivity returns a new 'Announce' activity.
func NewAnnounceActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeAnnounce),
			WithTo(options.To...),
			WithPublishedTime(options.Published),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
		},
	}
}

// NewFollowActivity returns a new 'Follow' activity.
func NewFollowActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeFollow),
			WithTo(options.To...),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
		},
	}
}

// NewInviteActivity returns a new 'InviteWitness' activity.
func NewInviteActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextActivityAnchors)...),
			WithID(options.ID),
			WithType(TypeInvite),
			WithTo(options.To...),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
			Target: options.Target,
		},
	}
}

// NewAcceptActivity returns a new 'Accept' activity.
func NewAcceptActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeAccept),
			WithTo(options.To...),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
			Result: options.Result,
		},
	}
}

// NewRejectActivity returns a new 'Reject' activity.
func NewRejectActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeReject),
			WithTo(options.To...),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
		},
	}
}

// NewLikeActivity returns a new 'Like' activity.
func NewLikeActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeLike),
			WithTo(options.To...),
			WithPublishedTime(options.Published),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
			Result: options.Result,
		},
	}
}

// NewOfferActivity returns a new 'Offer' activity.
func NewOfferActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeOffer),
			WithTo(options.To...),
			WithStartTime(options.StartTime),
			WithEndTime(options.EndTime),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
			Target: options.Target,
		},
	}
}

// NewUndoActivity returns a new 'Undo' activity.
func NewUndoActivity(obj *ObjectProperty, opts ...Opt) *ActivityType {
	options := NewOptions(opts...)

	return &ActivityType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams)...),
			WithID(options.ID),
			WithType(TypeUndo),
			WithTo(options.To...),
		),
		activity: &activityType{
			Actor:  NewURLProperty(options.Actor),
			Object: obj,
		},
	}
}
