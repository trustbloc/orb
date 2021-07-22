/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package model

import (
	"fmt"
)

// ErrResourceNotFound is an error type used to indicate that a given resource could not be found.
var ErrResourceNotFound = fmt.Errorf("resource not found")
