package llm

import "strings"

// Price is the cost of a model in USD per million tokens.
type Price struct {
	Input  float64
	Output float64
	// CacheRead and CacheWrite price cached input. Zero means "derive from
	// Input": reads at 10 percent, writes at 125 percent.
	CacheRead  float64
	CacheWrite float64
}

// builtinPrices holds first-party list prices for models Spackle can name
// with confidence. Source: Anthropic's published model table, as of
// 2026-11-03. Prices change; [pricing] in spackle.toml overrides any entry
// and adds models that are not listed. A model with no price is reported as
// "cost unknown" rather than guessed.
//
// Only Anthropic's first-party prices are built in. OpenAI-compatible
// endpoints differ per vendor and reseller, so those come from config or
// from the cost the endpoint reports (OpenRouter does).
var builtinPrices = map[string]Price{
	"claude-fable-5-2":  {Input: 8, Output: 40, CacheRead: 0.20},
	"claude-mythos-5-2": {Input: 8, Output: 40, CacheRead: 0.20},
	"claude-fable-5-1":  {Input: 10, Output: 50},
	"claude-fable-5":    {Input: 10, Output: 50},
	"claude-opus-5-5":   {Input: 4, Output: 20, CacheRead: 0.20},
	"claude-opus-5":     {Input: 5, Output: 25},
	"claude-opus-4-8":   {Input: 5, Output: 25},
	"claude-opus-4-7":   {Input: 5, Output: 25},
	"claude-opus-4-6":   {Input: 5, Output: 25},
	"claude-sonnet-5-5": {Input: 2, Output: 10, CacheRead: 0.10},
	"claude-sonnet-5":   {Input: 2, Output: 10},
	"claude-sonnet-4-6": {Input: 3, Output: 15},
	// Haiku 5.5 costs more for prompts above 100K tokens. Spackle's prompts
	// stay well under that, so the base rate is used.
	"claude-haiku-5-5": {Input: 0.10, Output: 0.50},
	"claude-haiku-4-5": {Input: 1, Output: 5},
}

// Pricer looks up model prices.
type Pricer struct {
	overrides map[string]Price
}

// NewPricer returns a Pricer with the given overrides on top of the built-in
// table.
func NewPricer(overrides map[string]Price) Pricer {
	return Pricer{overrides: overrides}
}

// Lookup returns the price of a model and whether it is known.
func (p Pricer) Lookup(model string) (Price, bool) {
	if pr, ok := p.overrides[model]; ok {
		return pr, true
	}
	if pr, ok := builtinPrices[model]; ok {
		return pr, true
	}
	// Routers name models as vendor/model, for example anthropic/claude-opus-5-5.
	if _, bare, ok := strings.Cut(model, "/"); ok {
		if pr, ok := p.overrides[bare]; ok {
			return pr, true
		}
	}
	return Price{}, false
}

// Cost fills in CostUSD and CostKnown on a usage record. Local providers
// cost nothing. A cost the provider reported itself is kept.
func (p Pricer) Cost(model string, local bool, u Usage) Usage {
	if local {
		u.CostUSD, u.CostKnown = 0, true
		return u
	}
	if u.CostKnown {
		return u
	}
	price, ok := p.Lookup(model)
	if !ok {
		u.CostUSD, u.CostKnown = 0, false
		return u
	}
	read, write := price.CacheRead, price.CacheWrite
	if read == 0 {
		read = price.Input * 0.10
	}
	if write == 0 {
		write = price.Input * 1.25
	}
	plain := u.InputTokens - u.CachedInputTokens - u.CacheWriteTokens
	if plain < 0 {
		plain = 0
	}
	u.CostUSD = (float64(plain)*price.Input +
		float64(u.CachedInputTokens)*read +
		float64(u.CacheWriteTokens)*write +
		float64(u.OutputTokens)*price.Output) / 1e6
	u.CostKnown = true
	return u
}

// EstimateCost prices a hypothetical number of tokens, for the estimate
// shown before a paid run.
func (p Pricer) EstimateCost(model string, local bool, inputTokens, outputTokens int) (float64, bool) {
	u := p.Cost(model, local, Usage{InputTokens: inputTokens, OutputTokens: outputTokens})
	return u.CostUSD, u.CostKnown
}
