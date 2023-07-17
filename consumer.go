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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"unsafe"
)

type ConsumeFuzzer struct {
	data                 []byte
	dataTotal            uint32
	CommandPart          []byte
	RestOfArray          []byte
	NumberOfCalls        int
	position             uint32
	fuzzUnexportedFields bool
	curDepth             int
	Funcs                map[reflect.Type]reflect.Value
	DisallowUnknownTypes bool
	MaxDepth             int
	MaxTotalLen          uint32
}

func IsDivisibleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func NewConsumer(fuzzData []byte) *ConsumeFuzzer {
	return &ConsumeFuzzer{
		data:        fuzzData,
		dataTotal:   uint32(len(fuzzData)),
		Funcs:       make(map[reflect.Type]reflect.Value),
		curDepth:    0,
		MaxDepth:    100,
		MaxTotalLen: 2000000,
	}
}

func (f *ConsumeFuzzer) Split(minCalls, maxCalls int) error {
	if f.dataTotal == 0 {
		return errors.New("could not split")
	}
	numberOfCalls := int(f.data[0])
	if numberOfCalls < minCalls || numberOfCalls > maxCalls {
		return errors.New("bad number of calls")
	}
	if int(f.dataTotal) < numberOfCalls+numberOfCalls+1 {
		return errors.New("length of data does not match required parameters")
	}

	// Define part 2 and 3 of the data array
	commandPart := f.data[1 : numberOfCalls+1]
	restOfArray := f.data[numberOfCalls+1:]

	// Just a small check. It is necessary
	if len(commandPart) != numberOfCalls {
		return errors.New("length of commandPart does not match number of calls")
	}

	// Check if restOfArray is divisible by numberOfCalls
	if !IsDivisibleBy(len(restOfArray), numberOfCalls) {
		return errors.New("length of commandPart does not match number of calls")
	}
	f.CommandPart = commandPart
	f.RestOfArray = restOfArray
	f.NumberOfCalls = numberOfCalls
	return nil
}

func (f *ConsumeFuzzer) AllowUnexportedFields() {
	f.fuzzUnexportedFields = true
}

func (f *ConsumeFuzzer) DisallowUnexportedFields() {
	f.fuzzUnexportedFields = false
}

func (f *ConsumeFuzzer) GenerateStruct(targetStruct interface{}) error {
	e := reflect.ValueOf(targetStruct).Elem()
	return f.fuzzStruct(e, false)
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
		F: f,
	})})

	// check if we return an error
	if verr[0].IsNil() {
		return nil
	}
	return fmt.Errorf("could not use a custom function")
}

func (f *ConsumeFuzzer) fuzzStruct(e reflect.Value, customFunctions bool) error {
	if f.curDepth >= f.MaxDepth {
		// return err or nil here?
		return nil
	}
	f.curDepth++
	defer func() { f.curDepth-- }()

	// We check if we should check for custom functions
	if customFunctions && e.IsValid() && e.CanAddr() {
		err := f.setCustom(e.Addr())
		if err != nil {
			return err
		}
	}

	switch e.Kind() {
	case reflect.Struct:
		for i := 0; i < e.NumField(); i++ {
			var v reflect.Value
			if !e.Field(i).CanSet() {
				if f.fuzzUnexportedFields {
					v = reflect.NewAt(e.Field(i).Type(), unsafe.Pointer(e.Field(i).UnsafeAddr())).Elem()
				}
				if err := f.fuzzStruct(v, customFunctions); err != nil {
					return err
				}
			} else {
				v = e.Field(i)
				if err := f.fuzzStruct(v, customFunctions); err != nil {
					return err
				}
			}
		}
	case reflect.String:
		str, err := f.GetString()
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

		randQty, err := f.GetUint32()
		if err != nil {
			return err
		}
		numOfElements := randQty % maxElements
		if (f.dataTotal - f.position) < numOfElements {
			numOfElements = f.dataTotal - f.position
		}

		uu := reflect.MakeSlice(e.Type(), int(numOfElements), int(numOfElements))

		for i := 0; i < int(numOfElements); i++ {
			// If we have more than 10, then we can proceed with that.
			if err := f.fuzzStruct(uu.Index(i), customFunctions); err != nil {
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
		newInt, err := f.GetUint16()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint32:
		newInt, err := f.GetUint32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Uint64:
		newInt, err := f.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetUint(uint64(newInt))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		newInt, err := f.GetInt()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetInt(int64(newInt))
		}
	case reflect.Float32:
		newFloat, err := f.GetFloat32()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Float64:
		newFloat, err := f.GetFloat64()
		if err != nil {
			return err
		}
		if e.CanSet() {
			e.SetFloat(float64(newFloat))
		}
	case reflect.Bool:
		newBool, err := f.GetBool()
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
			randQty, err := f.GetInt()
			if err != nil {
				return err
			}
			numOfElements := randQty % maxElements
			for i := 0; i < numOfElements; i++ {
				key := reflect.New(e.Type().Key()).Elem()
				if err := f.fuzzStruct(key, customFunctions); err != nil {
					return err
				}
				val := reflect.New(e.Type().Elem()).Elem()
				if err = f.fuzzStruct(val, customFunctions); err != nil {
					return err
				}
				e.SetMapIndex(key, val)
			}
		}
	case reflect.Ptr:
		if e.CanSet() {
			e.Set(reflect.New(e.Type().Elem()))
			if err := f.fuzzStruct(e.Elem(), customFunctions); err != nil {
				return err
			}
			return nil
		}
	case reflect.Uint8:
		b, err := f.GetByte()
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

func (f *ConsumeFuzzer) GetStringArray() (reflect.Value, error) {
	// The max size of the array:
	const max uint32 = 20

	arraySize := f.position
	if arraySize > max {
		arraySize = max
	}
	stringArray := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf("string")), int(arraySize), int(arraySize))
	if f.position+arraySize >= f.dataTotal {
		return stringArray, errors.New("could not make string array")
	}

	for i := 0; i < int(arraySize); i++ {
		stringSize := uint32(f.data[f.position])
		if f.position+stringSize >= f.dataTotal {
			return stringArray, nil
		}
		stringToAppend := string(f.data[f.position : f.position+stringSize])
		strVal := reflect.ValueOf(stringToAppend)
		stringArray = reflect.Append(stringArray, strVal)
		f.position += stringSize
	}
	return stringArray, nil
}

func (f *ConsumeFuzzer) GetInt() (int, error) {
	if f.position >= f.dataTotal {
		return 0, errors.New("not enough bytes to create int")
	}
	returnInt := int(f.data[f.position])
	f.position++
	return returnInt, nil
}

func (f *ConsumeFuzzer) GetByte() (byte, error) {
	if f.position >= f.dataTotal {
		return 0x00, errors.New("not enough bytes to get byte")
	}
	returnByte := f.data[f.position]
	f.position++
	return returnByte, nil
}

func (f *ConsumeFuzzer) GetNBytes(numberOfBytes int) ([]byte, error) {
	if f.position >= f.dataTotal {
		return nil, errors.New("not enough bytes to get byte")
	}
	returnBytes := make([]byte, 0, numberOfBytes)
	for i := 0; i < numberOfBytes; i++ {
		newByte, err := f.GetByte()
		if err != nil {
			return nil, err
		}
		returnBytes = append(returnBytes, newByte)
	}
	return returnBytes, nil
}

func (f *ConsumeFuzzer) GetUint16() (uint16, error) {
	u16, err := f.GetNBytes(2)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		return binary.LittleEndian.Uint16(u16), nil
	}
	return binary.BigEndian.Uint16(u16), nil
}

func (f *ConsumeFuzzer) GetUint32() (uint32, error) {
	i, err := f.GetInt()
	if err != nil {
		return uint32(0), err
	}
	return uint32(i), nil
}

func (f *ConsumeFuzzer) GetUint64() (uint64, error) {
	u64, err := f.GetNBytes(8)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		return binary.LittleEndian.Uint64(u64), nil
	}
	return binary.BigEndian.Uint64(u64), nil
}

func (f *ConsumeFuzzer) GetBytes() ([]byte, error) {
	if f.position >= f.dataTotal {
		return nil, errors.New("not enough bytes to create byte array")
	}
	length, err := f.GetUint32()
	if err != nil {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if f.position+length > f.MaxTotalLen {
		return nil, errors.New("created too large a string")
	}
	byteBegin := f.position - 1
	if byteBegin >= f.dataTotal {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if length == 0 {
		return nil, errors.New("zero-length is not supported")
	}
	if byteBegin+length >= f.dataTotal {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if byteBegin+length < byteBegin {
		return nil, errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return f.data[byteBegin:f.position], nil
}

func (f *ConsumeFuzzer) GetString() (string, error) {
	if f.position >= f.dataTotal {
		return "nil", errors.New("not enough bytes to create string")
	}
	length, err := f.GetUint32()
	if err != nil {
		return "nil", errors.New("not enough bytes to create string")
	}
	if f.position > f.MaxTotalLen {
		return "nil", errors.New("created too large a string")
	}
	byteBegin := f.position
	if byteBegin >= f.dataTotal {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin+length > f.dataTotal {
		return "nil", errors.New("not enough bytes to create string")
	}
	if byteBegin > byteBegin+length {
		return "nil", errors.New("numbers overflow")
	}
	f.position = byteBegin + length
	return string(f.data[byteBegin:f.position]), nil
}

func (f *ConsumeFuzzer) GetBool() (bool, error) {
	if f.position >= f.dataTotal {
		return false, errors.New("not enough bytes to create bool")
	}
	if IsDivisibleBy(int(f.data[f.position]), 2) {
		f.position++
		return true, nil
	} else {
		f.position++
		return false, nil
	}
}

func (f *ConsumeFuzzer) FuzzMap(m interface{}) error {
	return f.GenerateStruct(m)
}

// GetStringFrom returns a string that can only consist of characters
// included in possibleChars. It returns an error if the created string
// does not have the specified length.
func (f *ConsumeFuzzer) GetStringFrom(possibleChars string, length int) (string, error) {
	if (f.dataTotal - f.position) < uint32(length) {
		return "", errors.New("not enough bytes to create a string")
	}
	output := make([]byte, 0, length)
	for i := 0; i < length; i++ {
		charIndex, err := f.GetInt()
		if err != nil {
			return string(output), err
		}
		output = append(output, possibleChars[charIndex%len(possibleChars)])
	}
	return string(output), nil
}

func (f *ConsumeFuzzer) GetRune() ([]rune, error) {
	stringToConvert, err := f.GetString()
	if err != nil {
		return []rune("nil"), err
	}
	return []rune(stringToConvert), nil
}

func (f *ConsumeFuzzer) GetFloat32() (float32, error) {
	u32, err := f.GetNBytes(4)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		u32LE := binary.LittleEndian.Uint32(u32)
		return math.Float32frombits(u32LE), nil
	}
	u32BE := binary.BigEndian.Uint32(u32)
	return math.Float32frombits(u32BE), nil
}

func (f *ConsumeFuzzer) GetFloat64() (float64, error) {
	u64, err := f.GetNBytes(8)
	if err != nil {
		return 0, err
	}
	littleEndian, err := f.GetBool()
	if err != nil {
		return 0, err
	}
	if littleEndian {
		u64LE := binary.LittleEndian.Uint64(u64)
		return math.Float64frombits(u64LE), nil
	}
	u64BE := binary.BigEndian.Uint64(u64)
	return math.Float64frombits(u64BE), nil
}

func (f *ConsumeFuzzer) CreateSlice(targetSlice interface{}) error {
	return f.GenerateStruct(targetSlice)
}
