/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/orb/pkg/anchor/proof"
)

func TestNew(t *testing.T) {
	wp, err := New("OutOf(2,system)")
	require.NoError(t, err)
	require.NotNil(t, wp)

	wp, err = New("OutOf(a,system)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer")

	wp, err = New("OutOf(2,batch)")
	require.NoError(t, err)
	require.NotNil(t, wp)

	wp, err = New("OutOf(2,invalid)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "role 'invalid' not supported for OutOf policy")

	wp, err = New("OutOf(2,system,other)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "expected 2 but got 3 arguments for OutOf")

	wp, err = New("OutOf(a,system)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer")

	wp, err = New("MinPercent(70,batch)")
	require.NoError(t, err)
	require.NotNil(t, wp)

	wp, err = New("MinPercent(70,invalid)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "role 'invalid' not supported for MinPercent policy")

	wp, err = New("MinPercent(invalid,batch)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer between 0 and 100: strconv.Atoi")

	wp, err = New("MinPercent(150,batch)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "first argument for OutOf policy must be an integer between 0 and 100")

	wp, err = New("MinPercent(20,system,other)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "expected 2 but got 3 arguments for MinPercent")

	wp, err = New("Test(2,3)")
	require.Error(t, err)
	require.Nil(t, wp)
	require.Contains(t, err.Error(), "rule not supported: Test(2,3)")
}

func TestEvaluate(t *testing.T) {
	t.Run("success - default policy satisfied (100% batch and 100% system)", func(t *testing.T) {
		wp, err := New("")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "witness-1",
				Proof:   []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy not satisfied (no proofs)", func(t *testing.T) {
		wp, err := New("OutOf(1,system)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy not satisfied (no system proofs)", func(t *testing.T) {
		wp, err := New("OutOf(1,system)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, false, ok)
	})

	t.Run("success - policy satisfied (all batch witness proofs(default), one system witness proof)", func(t *testing.T) {
		wp, err := New("OutOf(1,system)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs, 50% system witness proofs)", func(t *testing.T) {
		wp, err := New("MinPercent(50,system) AND MinPercent(50,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs or 50% system witness proofs)", func(t *testing.T) {
		wp, err := New("MinPercent(50,system) OR MinPercent(50,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (50% batch witness proofs or 50% system witness proofs)", func(t *testing.T) {
		wp, err := New("MinPercent(50,system) OR MinPercent(50,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - policy satisfied (all batch witness proofs(default), one system witness proof)", func(t *testing.T) {
		wp, err := New("OutOf(1,system)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-2",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
				Proof:   []byte("proof"),
			},
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-2",
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - no system witnesses provided", func(t *testing.T) {
		wp, err := New("MinPercent(50,system) AND MinPercent(50,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeBatch,
				Witness: "batch-witness-1",
				Proof:   []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})

	t.Run("success - no batch witnesses provided", func(t *testing.T) {
		wp, err := New("MinPercent(50,system) AND MinPercent(50,batch)")
		require.NoError(t, err)
		require.NotNil(t, wp)

		witnessProofs := []*proof.WitnessProof{
			{
				Type:    proof.WitnessTypeSystem,
				Witness: "system-witness-1",
				Proof:   []byte("proof"),
			},
		}

		ok, err := wp.Evaluate(witnessProofs)
		require.NoError(t, err)
		require.Equal(t, true, ok)
	})
}
