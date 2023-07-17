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

package bytesource

import (
	"encoding/binary"
	"errors"
	"math"
)

type ByteSource struct {
	data         []byte
	dataTotal    uint32
	position     uint32
	maxStringLen uint32
}

// New returns a new ByteSource from a given slice of bytes.
func New(input []byte, maxStringLen uint32) *ByteSource {
	s := &ByteSource{
		data:         input,
		dataTotal:    uint32(len(input)),
		position:     0,
		maxStringLen: maxStringLen,
	}
	return s
}

func IsDivisibleBy(n int, divisibleby int) bool {
	return (n % divisibleby) == 0
}

func (f *ByteSource) GetInt() (int, error) {
	if f.position >= uint32(f.dataTotal) {
		return 0, errors.New("not enough bytes to create int")
	}
	returnInt := int(f.data[f.position])
	f.position++
	return returnInt, nil
}

func (f *ByteSource) GetByte() (byte, error) {
	if f.position >= f.dataTotal {
		return 0x00, errors.New("not enough bytes to get byte")
	}
	returnByte := f.data[f.position]
	f.position++
	return returnByte, nil
}

func (f *ByteSource) GetNBytes(numberOfBytes int) ([]byte, error) {
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

func (f *ByteSource) GetUint16() (uint16, error) {
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

func (f *ByteSource) GetUint32() (uint32, error) {
	i, err := f.GetInt()
	if err != nil {
		return uint32(0), err
	}
	return uint32(i), nil
}

func (f *ByteSource) GetUint64() (uint64, error) {
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

func (f *ByteSource) GetBytes() ([]byte, error) {
	if f.position >= f.dataTotal {
		return nil, errors.New("not enough bytes to create byte array")
	}
	length, err := f.GetUint32()
	if err != nil {
		return nil, errors.New("not enough bytes to create byte array")
	}
	if f.position+length > f.maxStringLen {
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

func (f *ByteSource) GetString() (string, error) {
	if f.position >= f.dataTotal {
		return "nil", errors.New("not enough bytes to create string")
	}
	length, err := f.GetUint32()
	if err != nil {
		return "nil", errors.New("not enough bytes to create string")
	}
	if f.position > f.maxStringLen {
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

func (f *ByteSource) GetBool() (bool, error) {
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

// GetStringFrom returns a string that can only consist of characters
// included in possibleChars. It returns an error if the created string
// does not have the specified length.
func (f *ByteSource) GetStringFrom(possibleChars string, length int) (string, error) {
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

func (f *ByteSource) GetRune() ([]rune, error) {
	stringToConvert, err := f.GetString()
	if err != nil {
		return []rune("nil"), err
	}
	return []rune(stringToConvert), nil
}

func (f *ByteSource) GetFloat32() (float32, error) {
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

func (f *ByteSource) GetFloat64() (float64, error) {
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
