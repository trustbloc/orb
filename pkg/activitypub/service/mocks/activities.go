/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
)

// Activities contains a slice of ActivityType.
type Activities []*vocab.ActivityType

// QueryByType returns the activities that match the given types.
func (a Activities) QueryByType(types ...vocab.Type) Activities {
	var result Activities

	for _, activity := range a {
		if activity.Type().Is(types...) {
			result = append(result, activity)
		}
	}

	return result
}
