// Copyright 2023 The go-fuzz-headers Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gofuzzheaders

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/AdaLogics/go-fuzz-headers/bytesource"
)

type ConsumeFuzzer struct {
	source               *bytesource.ByteSource
	CommandPart          []byte
	RestOfArray          []byte
	NumberOfCalls        int
	fuzzUnexportedFields bool
	curDepth             int
	Funcs                map[reflect.Type]reflect.Value
	DisallowUnknownTypes bool
	DisallowCustomFuncs  bool
	MaxDepth             int
}

func NewConsumer(fuzzData []byte) *ConsumeFuzzer {
	return &ConsumeFuzzer{
		source:   bytesource.New(fuzzData, 2000000),
		Funcs:    make(map[reflect.Type]reflect.Value),
		curDepth: 0,
		MaxDepth: 100,
	}
}

func (f *ConsumeFuzzer) AllowUnexportedFields() {
	f.fuzzUnexportedFields = true
}

func (f *ConsumeFuzzer) DisallowUnexportedFields() {
	f.fuzzUnexportedFields = false
}

func (f *ConsumeFuzzer) GenerateStruct(targetStruct interface{}) error {
	e := reflect.ValueOf(targetStruct).Elem()
	return f.fuzzStruct(e)
}

func (f *ConsumeFuzzer) setCustom(v reflect.Value) error {
	// First: see if we have a fuzz function for it.
	doCustom, ok := f.Funcs[v.Type()]
	if !ok {
		return fmt.Errorf("could not find a custom function")
	}

	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("could not use a custom function")
			}
			v.Set(reflect.New(v.Type().Elem()))
		}
	case reflect.Map:
		if v.IsNil() {
			if !v.CanSet() {
				return fmt.Errorf("could not use a custom function")
			}
			v.Set(reflect.MakeMap(v.Type()))
		}
	default:
		return fmt.Errorf("could not use a custom function")
	}

	verr := doCustom.Call([]reflect.Value{v, reflect.ValueOf(Continue{
		f: f,
	})})

	// check if we return an error
	if verr[0].IsNil() {
		return nil
	}
	if err, ok := verr[0].Interface().(error); ok {
		return fmt.Errorf("could not use a custom function: %w", err)
	}
	return fmt.Errorf("could not use a custom function: %s", verr[0].String())
}

func (f *ConsumeFuzzer) fuzzStruct(e reflect.Value) error {
	if f.curDepth >= f.MaxDepth {
		// return err or nil here?
		return nil
	}
	f.curDepth++
	defer func() { f.curDepth-- }()

	// We check if we should check for custom functions
	if !f.DisallowCustomFuncs && e.IsValid() && e.CanAddr() && f.hasCustomFunction(e.Addr()) {
		return f.setCustom(e.Addr())
	}

	switch e.Kind() {
	case reflect.Struct:
		for i := 0; i < e.NumField(); i++ {
			var v reflect.Value
			if !e.Field(i).CanSet() {
				if f.fuzzUnexportedFields {
					v = reflect.NewAt(e.Field(i).Type(), unsafe.Pointer(e.Field(i).UnsafeAddr())).Elem()
				}
				if err := f.fuzzStruct(v); err != nil {
					return err
				}
			} else {
				v = e.Field(i)
				if err := f.fuzzStruct(v); err != nil {
					return err
				}
			}
		}
	case reflect.String:
		str, err := f.source.GetString()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetString(str)
		}
	case reflect.Slice:
		var maxElements uint32
		// Byte slices should not be restricted
		if e.Type().String() == "[]uint8" {
			maxElements = 10000000
		} else {
			maxElements = 50
		}

		randQty, err := f.source.GetUint32()
		if err != nil {
			return err
		}
		numOfElements := randQty % maxElements

		uu := reflect.MakeSlice(e.Type(), int(numOfElements), int(numOfElements))

		for i := 0; i < int(numOfElements); i++ {
			// If we have more than 10, then we can proceed with that.
			if err := f.fuzzStruct(uu.Index(i)); err != nil {
				if i >= 10 {
					if e.CanSet() {
						e.Set(uu)
					}
					return nil
				} else {
					return err
				}
			}
		}
		if e.CanSet() {
			e.Set(uu)
		}
	case reflect.Uint16:
		newInt, err := f.source.GetUint16()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint32:
		newInt, err := f.source.GetUint32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint64:
		newInt, err := f.source.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		newInt, err := f.source.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetInt(int64(newInt))
		}
	case reflect.Float32:
		newFloat, err := f.source.GetFloat32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Float64:
		newFloat, err := f.source.GetFloat64()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Bool:
		newBool, err := f.source.GetBool()
		if err != nil {
			return err
		}

		if e.CanSet() {
			e.SetBool(newBool)
		}
	case reflect.Map:
		if e.CanSet() {
			e.Set(reflect.MakeMap(e.Type()))
			const maxElements = 50
			randQty, err := f.source.GetInt()
			if err != nil {
				return err
			}
			numOfElements := randQty % maxElements
			for i := 0; i < numOfElements; i++ {
				key := reflect.New(e.Type().Key()).Elem()
				if err := f.fuzzStruct(key); err != nil {
					return err
				}
				val := reflect.New(e.Type().Elem()).Elem()
				if err = f.fuzzStruct(val); err != nil {
					return err
				}
				e.SetMapIndex(key, val)
			}
		}
	case reflect.Ptr:
		if e.CanSet() {
			e.Set(reflect.New(e.Type().Elem()))
			if err := f.fuzzStruct(e.Elem()); err != nil {
				return err
			}
			return nil
		}
	case reflect.Uint8:
		b, err := f.source.GetByte()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(b))
		}
	default:
		if f.DisallowUnknownTypes {
			if !e.IsValid() {
				return fmt.Errorf("unknown invalid type: %s", e.String())
			}
			return fmt.Errorf("unknown type: kind: %s: %s", e.Kind(), e.String())
		}
	}
	return nil
}

func (f *ConsumeFuzzer) hasCustomFunction(v reflect.Value) bool {
	_, ok := f.Funcs[v.Type()]
	return ok
}
