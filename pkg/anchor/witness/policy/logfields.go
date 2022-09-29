/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package policy

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/trustbloc/orb/pkg/anchor/witness/policy/config"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
)

const (
	fieldWitnessPolicyConfig = "policy-config"
	fieldEvaluatedTo         = "evaluated-to"
	fieldBatchCondition      = "batch-condition"
	fieldSystemCondition     = "system-condition"
	fieldWitnesses           = "witnesses"
	fieldBatchWitnesses      = "batch-witnesses"
	fieldSystemWitnesses     = "system-witnesses"
	fieldEligibleWitnesses   = "eligible-witnesses"
	fieldPreferredWitnesses  = "preferred-witnesses"
)

func withPolicyConfigField(value *config.WitnessPolicyConfig) zap.Field {
	return zap.Object(fieldWitnessPolicyConfig, newConfigMarshaller(value))
}

func withEvaluatedField(value bool) zap.Field {
	return zap.Bool(fieldEvaluatedTo, value)
}

func withBatchConditionField(value bool) zap.Field {
	return zap.Bool(fieldBatchCondition, value)
}

func withSystemConditionField(value bool) zap.Field {
	return zap.Bool(fieldSystemCondition, value)
}

func withWitnessesField(value []*proof.Witness) zap.Field {
	return zap.Array(fieldWitnesses, newWitnessArrayMarshaller(value))
}

func withBatchWitnessesField(value []*proof.Witness) zap.Field {
	return zap.Array(fieldBatchWitnesses, newWitnessArrayMarshaller(value))
}

func withSystemWitnessesField(value []*proof.Witness) zap.Field {
	return zap.Array(fieldSystemWitnesses, newWitnessArrayMarshaller(value))
}

func withEligibleWitnessesField(value []*proof.Witness) zap.Field {
	return zap.Array(fieldEligibleWitnesses, newWitnessArrayMarshaller(value))
}

func withPreferredWitnessesField(value []*proof.Witness) zap.Field {
	return zap.Array(fieldPreferredWitnesses, newWitnessArrayMarshaller(value))
}

func withWitnessProofsField(value []*proof.WitnessProof) zap.Field {
	return zap.Array(fieldWitnesses, newWitnessProofArrayMarshaller(value))
}

type configMarshaller struct {
	cfg *config.WitnessPolicyConfig
}

func newConfigMarshaller(cfg *config.WitnessPolicyConfig) *configMarshaller {
	return &configMarshaller{cfg: cfg}
}

func (m *configMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if m.cfg.MinNumberBatch > 0 {
		e.AddInt("minBatch", m.cfg.MinNumberBatch)
	}

	if m.cfg.MinNumberSystem > 0 {
		e.AddInt("minSystem", m.cfg.MinNumberSystem)
	}

	if m.cfg.MinPercentBatch > 0 {
		e.AddInt("minPercentBatch", m.cfg.MinPercentBatch)
	}

	if m.cfg.MinPercentSystem > 0 {
		e.AddInt("minPercentSystem", m.cfg.MinPercentSystem)
	}

	e.AddString("operator", m.cfg.Operator)
	e.AddBool("logRequired", m.cfg.LogRequired)

	return nil
}

type witnessMarshaller struct {
	w *proof.Witness
}

func newWitnessMarshaller(witness *proof.Witness) *witnessMarshaller {
	return &witnessMarshaller{w: witness}
}

func (m *witnessMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if m.w == nil {
		return nil
	}

	e.AddString("type", string(m.w.Type))

	if m.w.URI != nil {
		e.AddString("uri", m.w.URI.String())
	} else {
		e.AddString("uri", "")
	}

	e.AddBool("hasLog", m.w.HasLog)

	return nil
}

type witnessProofMarshaller struct {
	wm *witnessMarshaller
	w  *proof.WitnessProof
}

func newWitnessProofMarshaller(witnessProof *proof.WitnessProof) *witnessProofMarshaller {
	return &witnessProofMarshaller{w: witnessProof, wm: newWitnessMarshaller(witnessProof.Witness)}
}

func (m *witnessProofMarshaller) MarshalLogObject(e zapcore.ObjectEncoder) error {
	if err := m.wm.MarshalLogObject(e); err != nil {
		return fmt.Errorf("marshal log object: %w", err)
	}

	if m.w == nil {
		return nil
	}

	e.AddString("proof", string(m.w.Proof))

	return nil
}

type witnessArrayMarshaller struct {
	items []*proof.Witness
}

func newWitnessArrayMarshaller(items []*proof.Witness) *witnessArrayMarshaller {
	return &witnessArrayMarshaller{items: items}
}

func (m *witnessArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, w := range m.items {
		if err := e.AppendObject(newWitnessMarshaller(w)); err != nil {
			return fmt.Errorf("marshal witness: %w", err)
		}
	}

	return nil
}

type witnessProofArrayMarshaller struct {
	items []*proof.WitnessProof
}

func newWitnessProofArrayMarshaller(items []*proof.WitnessProof) *witnessProofArrayMarshaller {
	return &witnessProofArrayMarshaller{items: items}
}

func (m *witnessProofArrayMarshaller) MarshalLogArray(e zapcore.ArrayEncoder) error {
	for _, w := range m.items {
		if err := e.AppendObject(newWitnessProofMarshaller(w)); err != nil {
			return fmt.Errorf("marshal witness proof: %w", err)
		}
	}

	return nil
}
