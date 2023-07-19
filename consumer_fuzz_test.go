package gofuzzheaders

import (
	"errors"
	"os"
	"testing"

	"github.com/AdaLogics/go-fuzz-headers/bytesource"
)

func skipIfTesting(f *testing.F) {
	v := "DEBUG_FUZZ"
	if os.Getenv(v) != "true" {
		f.Skip("Skipped fuzz test, enable with " + v)
	}
}

func FuzzStructBool(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)

		s := struct {
			B bool
		}{}

		if err := c.GenerateStruct(&s); err != nil {
			if errors.Is(err, bytesource.ErrNotEnoughBytes) {
				return
			}
			t.Fatalf("failed to generate struct: %v", err)
		}

		if s.B {
			panic("IT WORKS")
		}
	})
}

func FuzzStructPtr(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)

		s := struct {
			I *byte
		}{}

		if err := c.GenerateStruct(&s); err != nil {
			if errors.Is(err, bytesource.ErrNotEnoughBytes) {
				return
			}
			t.Fatalf("failed to generate struct: %v", err)
		}

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

		var a any

		if err := c.GenerateStruct(&a); err != nil {
			if errors.Is(err, bytesource.ErrNotEnoughBytes) {
				return
			}
			t.Fatalf("failed to generate struct: %v", err)
		}

		if a == "foo" {
			panic("IT WORKS")
		}
	})
}

func FuzzSliceAny(f *testing.F) {
	skipIfTesting(f)

	f.Fuzz(func(t *testing.T, input []byte) {
		c := NewConsumer(input)
		c.NilChance = 0
		c.AddFuncs([]any{func(a *any, c Continue) error {
			*a = "foo"
			return nil
		}})

		a := make([]any, 0)

		if err := c.GenerateStruct(&a); err != nil {
			if errors.Is(err, bytesource.ErrNotEnoughBytes) {
				return
			}
			t.Fatalf("failed to generate struct: %v", err)
		}

		if len(a) > 0 {
			for _, v := range a {
				if v != "foo" {
					return
				}
			}
			panic("IT WORKS")
		}
	})
}
