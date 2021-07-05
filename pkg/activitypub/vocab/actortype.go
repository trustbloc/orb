/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"net/url"
)

// PublicKeyType defines a public key object.
type PublicKeyType struct {
	ID           *URLProperty `json:"id"`
	Owner        *URLProperty `json:"owner"`
	PublicKeyPem string       `json:"publicKeyPem"`
}

// NewPublicKey returns a new public key object.
func NewPublicKey(opts ...Opt) *PublicKeyType {
	options := NewOptions(opts...)

	return &PublicKeyType{
		ID:           NewURLProperty(options.ID),
		Owner:        NewURLProperty(options.Owner),
		PublicKeyPem: options.PublicKeyPem,
	}
}

// ActorType defines an 'actor'.
type ActorType struct {
	*ObjectType

	actor *actorType
}

type actorType struct {
	PublicKey  *PublicKeyType `json:"publicKey"`
	Inbox      *URLProperty   `json:"inbox"`
	Outbox     *URLProperty   `json:"outbox"`
	Followers  *URLProperty   `json:"followers"`
	Following  *URLProperty   `json:"following"`
	Witnesses  *URLProperty   `json:"witnesses"`
	Witnessing *URLProperty   `json:"witnessing"`
	Liked      *URLProperty   `json:"liked"`
	Likes      *URLProperty   `json:"likes"`
	Shares     *URLProperty   `json:"shares"`
}

// PublicKey returns the actor's public key.
func (t *ActorType) PublicKey() *PublicKeyType {
	return t.actor.PublicKey
}

// Inbox returns the URL of the actor's inbox.
func (t *ActorType) Inbox() *url.URL {
	if t.actor.Inbox == nil {
		return nil
	}

	return t.actor.Inbox.URL()
}

// Outbox returns the URL of the actor's outbox.
func (t *ActorType) Outbox() *url.URL {
	if t.actor.Outbox == nil {
		return nil
	}

	return t.actor.Outbox.URL()
}

// Followers returns the URL of the actor's followers.
func (t *ActorType) Followers() *url.URL {
	if t.actor.Followers == nil {
		return nil
	}

	return t.actor.Followers.URL()
}

// Following returns the URL of what the actor is following.
func (t *ActorType) Following() *url.URL {
	if t.actor.Following == nil {
		return nil
	}

	return t.actor.Following.URL()
}

// Witnesses returns the URL of the actor's witnesses.
func (t *ActorType) Witnesses() *url.URL {
	if t.actor.Witnesses == nil {
		return nil
	}

	return t.actor.Witnesses.URL()
}

// Witnessing returns the URL of what the actor is witnessing.
func (t *ActorType) Witnessing() *url.URL {
	if t.actor.Witnessing == nil {
		return nil
	}

	return t.actor.Witnessing.URL()
}

// Liked returns the URL of what the actor has liked.
func (t *ActorType) Liked() *url.URL {
	if t.actor.Liked == nil {
		return nil
	}

	return t.actor.Liked.URL()
}

// MarshalJSON mmarshals the object to JSON.
func (t *ActorType) MarshalJSON() ([]byte, error) {
	return MarshalJSON(t.ObjectType, t.actor)
}

// UnmarshalJSON ummarshals the object from JSON.
func (t *ActorType) UnmarshalJSON(bytes []byte) error {
	t.ObjectType = NewObject()
	t.actor = &actorType{}

	return UnmarshalJSON(bytes, t.ObjectType, t.actor)
}

// NewService returns a new 'Service' actor type.
func NewService(id *url.URL, opts ...Opt) *ActorType {
	options := NewOptions(opts...)

	return &ActorType{
		ObjectType: NewObject(
			WithContext(getContexts(options, ContextActivityStreams, ContextSecurity, ContextOrb)...),
			WithID(id),
			WithType(TypeService),
		),
		actor: &actorType{
			PublicKey:  options.PublicKey,
			Inbox:      NewURLProperty(options.Inbox),
			Outbox:     NewURLProperty(options.Outbox),
			Followers:  NewURLProperty(options.Followers),
			Following:  NewURLProperty(options.Following),
			Witnesses:  NewURLProperty(options.Witnesses),
			Witnessing: NewURLProperty(options.Witnessing),
			Liked:      NewURLProperty(options.Liked),
			Likes:      NewURLProperty(options.Likes),
			Shares:     NewURLProperty(options.Shares),
		},
	}
}
