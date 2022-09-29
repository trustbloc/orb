/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/trustbloc/orb/internal/pkg/log/mocks"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	"github.com/trustbloc/orb/pkg/internal/testutil"
)

func TestConfigMarshaller(t *testing.T) {
	cfg := &config.WitnessPolicyConfig{
		MinNumberSystem:  2,
		MinNumberBatch:   3,
		MinPercentSystem: 50,
		MinPercentBatch:  25,
		Operator:         "OR",
		LogRequired:      true,
	}

	encoder := zapcore.NewMapObjectEncoder()

	require.NoError(t, newConfigMarshaller(cfg).MarshalLogObject(encoder))
	require.Equal(t, cfg.MinNumberSystem, encoder.Fields["minSystem"])
	require.Equal(t, cfg.MinNumberBatch, encoder.Fields["minBatch"])
	require.Equal(t, cfg.MinPercentSystem, encoder.Fields["minPercentSystem"])
	require.Equal(t, cfg.MinPercentBatch, encoder.Fields["minPercentBatch"])
	require.Equal(t, cfg.Operator, encoder.Fields["operator"])
	require.Equal(t, cfg.LogRequired, encoder.Fields["logRequired"])
}

func TestWitnessMarshaller(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		w := &proof.Witness{
			Type:   "system",
			URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com")),
			HasLog: true,
		}

		encoder := zapcore.NewMapObjectEncoder()

		require.NoError(t, newWitnessMarshaller(w).MarshalLogObject(encoder))
		require.Equal(t, string(w.Type), encoder.Fields["type"])
		require.Equal(t, w.URI.String(), encoder.Fields["uri"])
		require.Equal(t, w.HasLog, encoder.Fields["hasLog"])
	})

	t.Run("empty -> success", func(t *testing.T) {
		w := &proof.Witness{}

		encoder := zapcore.NewMapObjectEncoder()

		require.NoError(t, newWitnessMarshaller(w).MarshalLogObject(encoder))
		require.Empty(t, encoder.Fields["type"])
		require.Empty(t, encoder.Fields["uri"])
		require.Empty(t, encoder.Fields["hasLog"])
	})
}

func TestWitnessProofMarshaller(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		w := &proof.WitnessProof{
			Witness: &proof.Witness{
				Type:   "system",
				URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com")),
				HasLog: true,
			},
			Proof: []byte(`"id":"https://example.com/proof1"`),
		}

		encoder := zapcore.NewMapObjectEncoder()

		require.NoError(t, newWitnessProofMarshaller(w).MarshalLogObject(encoder))
		require.Equal(t, string(w.Type), encoder.Fields["type"])
		require.Equal(t, w.URI.String(), encoder.Fields["uri"])
		require.Equal(t, w.HasLog, encoder.Fields["hasLog"])
		require.Equal(t, string(w.Proof), encoder.Fields["proof"])
	})

	t.Run("empty -> success", func(t *testing.T) {
		w := &proof.WitnessProof{}

		encoder := zapcore.NewMapObjectEncoder()

		require.NoError(t, newWitnessProofMarshaller(w).MarshalLogObject(encoder))
		require.Empty(t, encoder.Fields["type"])
		require.Empty(t, encoder.Fields["uri"])
		require.Empty(t, encoder.Fields["hasLog"])
		require.Empty(t, encoder.Fields["proof"])
	})
}

func TestWitnessArrayMarshaller(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		w1 := &proof.Witness{
			Type:   "system",
			URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com/w1")),
			HasLog: true,
		}

		w2 := &proof.Witness{
			Type:   "batch",
			URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com/w2")),
			HasLog: false,
		}

		encoder := mocks.NewArrayEncoder()

		require.NoError(t, newWitnessArrayMarshaller([]*proof.Witness{w1, w2}).MarshalLogArray(encoder))

		require.Len(t, encoder.Items(), 2)

		fields, ok := encoder.Items()[0].(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, string(w1.Type), fields["type"])
		require.Equal(t, w1.URI.String(), fields["uri"])
		require.Equal(t, w1.HasLog, fields["hasLog"])

		fields, ok = encoder.Items()[1].(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, string(w2.Type), fields["type"])
		require.Equal(t, w2.URI.String(), fields["uri"])
		require.Equal(t, w2.HasLog, fields["hasLog"])
	})
}

func TestWitnessProofArrayMarshaller(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		w1 := &proof.WitnessProof{
			Witness: &proof.Witness{
				Type:   "system",
				URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com/w1")),
				HasLog: true,
			},
			Proof: []byte(`"id":"https://example.com/proof1"`),
		}

		w2 := &proof.WitnessProof{
			Witness: &proof.Witness{
				Type:   "batch",
				URI:    vocab.NewURLProperty(testutil.MustParseURL("http://example.com/w2")),
				HasLog: true,
			},
			Proof: []byte(`"id":"https://example.com/proof2"`),
		}

		encoder := mocks.NewArrayEncoder()

		require.NoError(t, newWitnessProofArrayMarshaller([]*proof.WitnessProof{w1, w2}).MarshalLogArray(encoder))

		require.Len(t, encoder.Items(), 2)

		fields, ok := encoder.Items()[0].(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, string(w1.Type), fields["type"])
		require.Equal(t, w1.URI.String(), fields["uri"])
		require.Equal(t, w1.HasLog, fields["hasLog"])
		require.Equal(t, string(w1.Proof), fields["proof"])

		fields, ok = encoder.Items()[1].(map[string]interface{})
		require.True(t, ok)

		require.Equal(t, string(w2.Type), fields["type"])
		require.Equal(t, w2.URI.String(), fields["uri"])
		require.Equal(t, w2.HasLog, fields["hasLog"])
		require.Equal(t, string(w2.Proof), fields["proof"])
	})
}
