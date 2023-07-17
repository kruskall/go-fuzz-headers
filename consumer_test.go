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
	"testing"
)

type TestStruct1 struct {
	Field1 string
	Field2 string
	Field3 []byte
}

func TestStruct_fuzzing1(t *testing.T) {
	data := []byte{
		0x03, 0x41, 0x42, 0x43, // Length and data of field 1 (= 2)
		0x03, 0x41, 0x42, 0x43, // Length and data of field 2 (= 3)
		0x01, 0x41, // Field3
	}

	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	if ts1.Field1 != "ABC" {
		t.Errorf("ts1.Field1 was %v but should be 'AB'", []byte(ts1.Field1))
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if string(ts1.Field3) != "A" {
		t.Errorf("ts1.Field3 was %v but should be 'A'", ts1.Field3)
	}
}

// Tests that we can create long byte slices in structs
func TestStruct_fuzzing2(t *testing.T) {
	data := []byte{
		0x03, 0x41, 0x42, 0x43, // Length field 1 (= 3)
		0x03, 0x41, 0x42, 0x43, // Content of Field3
		0x50,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // All of this
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // should go
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // into Field3
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	}

	ts1 := TestStruct1{}
	fuzz1 := NewConsumer(data)
	err := fuzz1.GenerateStruct(&ts1)
	if err != nil {
		t.Errorf("%v", err)
	}
	if ts1.Field1 != "ABC" {
		t.Errorf("ts1.Field1 was %v but should be 'ABC'", ts1.Field1)
	}
	if ts1.Field2 != "ABC" {
		t.Errorf("ts1.Field2 was %v but should be 'ABC'", ts1.Field2)
	}
	if len(ts1.Field3) != 80 {
		t.Errorf("ts1.Field3 was %v but should be 'ABCD'", ts1.Field3)
	}
}
