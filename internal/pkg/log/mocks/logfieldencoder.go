/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mocks

import (
	"time"

	"go.uber.org/zap/zapcore"
)

// ArrayEncoder implements a mock zapcore.ArrayEncoder.
type ArrayEncoder interface {
	zapcore.ArrayEncoder
	Items() []interface{}
}

type arrayEncoder struct {
	items []interface{}
}

// NewArrayEncoder returns a new mock array encoder.
func NewArrayEncoder() ArrayEncoder {
	return &arrayEncoder{}
}

func (e *arrayEncoder) Items() []interface{} {
	return e.items
}

func (e *arrayEncoder) AppendArray(v zapcore.ArrayMarshaler) error {
	enc := &arrayEncoder{}

	err := v.MarshalLogArray(enc)

	e.items = append(e.items, enc.items) //nolint:asasalint

	return err
}

func (e *arrayEncoder) AppendObject(v zapcore.ObjectMarshaler) error {
	m := zapcore.NewMapObjectEncoder()

	err := v.MarshalLogObject(m)

	e.items = append(e.items, m.Fields)

	return err
}

func (e *arrayEncoder) AppendReflected(v interface{}) error {
	e.items = append(e.items, v)

	return nil
}

func (e *arrayEncoder) AppendBool(v bool)              { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendByteString(v []byte)      { e.items = append(e.items, string(v)) }
func (e *arrayEncoder) AppendComplex128(v complex128)  { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendComplex64(v complex64)    { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendDuration(v time.Duration) { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendFloat64(v float64)        { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendFloat32(v float32)        { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendInt(v int)                { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendInt64(v int64)            { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendInt32(v int32)            { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendInt16(v int16)            { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendInt8(v int8)              { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendString(v string)          { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendTime(v time.Time)         { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUint(v uint)              { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUint64(v uint64)          { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUint32(v uint32)          { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUint16(v uint16)          { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUint8(v uint8)            { e.items = append(e.items, v) }
func (e *arrayEncoder) AppendUintptr(v uintptr)        { e.items = append(e.items, v) }
