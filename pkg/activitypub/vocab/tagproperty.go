/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vocab

import (
	"encoding/json"
	"fmt"
)

// TagProperty defines the 'tag' property.
type TagProperty struct {
	obj  *ObjectType
	link *LinkType
}

// NewTagProperty returns a new Tag property.
func NewTagProperty(opts ...Opt) *TagProperty {
	options := NewOptions(opts...)

	return &TagProperty{
		obj:  options.Object,
		link: options.Link,
	}
}

// Type returns the type of the tag property.
func (p *TagProperty) Type() *TypeProperty {
	if p == nil {
		return nil
	}

	if p.link != nil {
		return p.link.Type()
	}

	if p.obj != nil {
		return p.obj.Type()
	}

	return nil
}

// Link returns the link of the tag property. Nil is returned if the tag is not a Link type.
func (p *TagProperty) Link() *LinkType {
	if p == nil {
		return nil
	}

	return p.link
}

// Object returns the object of the tag property. Nil is returned if the tag is not an Object type.
func (p *TagProperty) Object() *ObjectType {
	if p == nil {
		return nil
	}

	return p.obj
}

// MarshalJSON marshals the 'tag' property.
func (p *TagProperty) MarshalJSON() ([]byte, error) {
	if p.obj != nil {
		return json.Marshal(p.obj)
	}

	if p.link != nil {
		return json.Marshal(p.link)
	}

	return nil, fmt.Errorf("neither object or link is set on the tag property")
}

// UnmarshalJSON unmarshals the 'tag' property.
func (p *TagProperty) UnmarshalJSON(bytes []byte) error {
	obj := &ObjectType{}

	err := json.Unmarshal(bytes, &obj)
	if err != nil {
		return err
	}

	switch {
	case obj.Type().Is(TypeLink):
		link := &LinkType{}

		e := json.Unmarshal(bytes, &link)
		if e != nil {
			return e
		}

		p.link = link

	default:
		p.obj = obj
	}

	return err
}
