/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package random

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

// New returns new random selector.
func New() *Selector {
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	return &Selector{}
}

// Selector implements random selection of n out of m witnesses.
type Selector struct{}

// Select selects n witnesses out of provided list of witnesses.
func (s *Selector) Select(witnesses []*proof.Witness, n int) ([]*proof.Witness, error) {
	l := len(witnesses)

	if n > l {
		return nil, fmt.Errorf("unable to select %d witnesses from witness array of length %d: %w",
			n, len(witnesses), orberrors.ErrWitnessesNotFound)
	}

	if n == l {
		return witnesses, nil
	}

	max := len(witnesses)

	var selected []*proof.Witness

	uniqueIndexes := make(map[int]bool)

	for i := 0; i < n; i++ {
		for {
			i := rand.Intn(max) //nolint:gosec

			if _, ok := uniqueIndexes[i]; !ok {
				uniqueIndexes[i] = true

				selected = append(selected, witnesses[i])

				break
			}
		}
	}

	return selected, nil
}
