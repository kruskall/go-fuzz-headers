package gofuzzheaders

type Option func(*ConsumeFuzzer)

type HandlingStrategy byte

const (
	IgnoreValue HandlingStrategy = iota
	KeepFuzzing
	FailWithError
)

func WithNilChance(f float32) Option {
	return func(cf *ConsumeFuzzer) {
		cf.nilChance = f
	}
}

func WithMaxDepth(i int64) Option {
	return func(cf *ConsumeFuzzer) {
		cf.maxDepth = i
	}
}

func WithUnexportedFieldStrategy(s HandlingStrategy) Option {
	return func(cf *ConsumeFuzzer) {
		cf.unexportedFieldStrategy = s
	}
}

func WithUnknownTypeStrategy(s HandlingStrategy) Option {
	return func(cf *ConsumeFuzzer) {
		cf.unknownTypeStrategy = s
	}
}

func WithoutCustomFuncs() Option {
	return func(cf *ConsumeFuzzer) {
		cf.disallowCustomFuncs = true
	}
}

func WithCustomFunction(f any) Option {
	return func(cf *ConsumeFuzzer) {
		cf.addFuncs([]any{f})
	}
}
