package gofuzzheaders

import (
	"errors"
	"os"
	"testing"

	"github.com/AdaLogics/go-fuzz-headers/bytesource"
)

func skipIfTesting(f *testing.F) {
	v := "DEBUG_FUZZ"
	if os.Getenv(v) != "1" {
		f.Skip("Skipped fuzz test, enable with " + v)
	}
}

func generate(t *testing.T, fuzzer *ConsumeFuzzer, a any) {
	t.Helper()

	if err := fuzzer.GenerateStruct(a); err != nil {
		if errors.Is(err, bytesource.ErrNotEnoughBytes) {
			t.SkipNow()
		}
		t.Fatalf("failed to generate struct: %v", err)
	}
}

func FuzzBool(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)

		s := struct {
			B bool
		}{}

		generate(t, c, &s)

		if s.B {
			panic("IT WORKS")
		}
	})
}

func FuzzPtr(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)

		s := struct {
			I *byte
		}{}

		generate(t, c, &s)

		if s.I == nil {
			panic("IT WORKS")
		}
	})
}

func FuzzAny(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)
		c.AddFuncs([]any{func(a *any, c Continue) error {
			*a = "foo"
			return nil
		}})

		s := struct {
			A any
		}{}

		generate(t, c, &s)

		if s.A == "foo" {
			panic("IT WORKS")
		}
	})
}

func FuzzSliceAny(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)
		c.AddFuncs([]any{func(a *any, c Continue) error {
			*a = "foo"
			return nil
		}})

		s := struct{
			A []any
		}{}

		generate(t, c, &s)

		if len(s.A) == 0 {
			return
		}

		for _, v := range s.A {
			if v != "foo" {
				return
			}
		}

		panic("IT WORKS")
	})
}
