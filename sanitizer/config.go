// Package sanitizer provides PII (Personally Identifiable Information) detection and redaction
// for structured data in Go applications. It supports regional patterns for Singapore, Malaysia,
// UAE, Thailand, and Hong Kong, with seamless integration for popular logging libraries.
package sanitizer

// Region represents a geographic region for PII pattern matching.
// Each region has specific PII patterns (national IDs, phone numbers, bank accounts).
//
// Example:
//
//	config := NewDefaultConfig().WithRegions(Singapore, Malaysia)
//	s := New(config)
type Region string

const (
	// Singapore enables Singapore-specific patterns (NRIC, phone, bank accounts)
	Singapore Region = "SG"

	// Malaysia enables Malaysia-specific patterns (MyKad, phone, bank accounts)
	Malaysia Region = "MY"

	// UAE enables UAE-specific patterns (Emirates ID, IBAN, phone)
	UAE Region = "AE"

	// Thailand enables Thailand-specific patterns (National ID, phone, bank accounts)
	Thailand Region = "TH"

	// HongKong enables Hong Kong-specific patterns (HKID, phone)
	HongKong Region = "HK"
)

// RedactionStrategy defines how PII should be redacted when detected.
//
// Example:
//
//	config := NewDefaultConfig().WithStrategy(StrategyPartial)
//	s := New(config)
type RedactionStrategy string

const (
	// StrategyFull replaces PII with "[REDACTED]" (default)
	StrategyFull RedactionStrategy = "full"

	// StrategyPartial masks part of the value, e.g., "****1234"
	// Use WithPartialMasking to configure mask character and visible chars
	StrategyPartial RedactionStrategy = "partial"

	// StrategyHash replaces PII with a consistent SHA-256 hash, e.g., "sha256:abc..."
	// Useful for log correlation while protecting actual values
	StrategyHash RedactionStrategy = "hash"

	// StrategyRemove completely removes the field from output
	StrategyRemove RedactionStrategy = "remove"
)

// Config holds the configuration for the sanitizer
type Config struct {
	// Region selection (default: all enabled)
	Regions []Region

	// Explicit lists (highest priority)
	AlwaysRedact []string // Field names to always redact
	NeverRedact  []string // Field names to never redact (allowlist)

	// Redaction strategy
	Strategy RedactionStrategy

	// For partial masking
	PartialMaskChar  rune
	PartialKeepLeft  int
	PartialKeepRight int

	// Performance tuning
	MaxDepth int // Max nesting depth for traversal

	// Custom patterns (advanced)
	CustomFieldPatterns   map[string][]string
	CustomContentPatterns []ContentPattern
}

// NewDefaultConfig creates a Config with sensible defaults
func NewDefaultConfig() *Config {
	return &Config{
		Regions:               []Region{Singapore, Malaysia, UAE, Thailand, HongKong},
		AlwaysRedact:          []string{},
		NeverRedact:           []string{},
		Strategy:              StrategyFull,
		PartialMaskChar:       '*',
		PartialKeepLeft:       0,
		PartialKeepRight:      4,
		MaxDepth:              10,
		CustomFieldPatterns:   make(map[string][]string),
		CustomContentPatterns: []ContentPattern{},
	}
}

// WithRedact adds fields to the explicit redact list
func (c *Config) WithRedact(fields ...string) *Config {
	c.AlwaysRedact = append(c.AlwaysRedact, fields...)
	return c
}

// WithPreserve adds fields to the explicit preserve list (never redact)
func (c *Config) WithPreserve(fields ...string) *Config {
	c.NeverRedact = append(c.NeverRedact, fields...)
	return c
}

// WithStrategy sets the redaction strategy
func (c *Config) WithStrategy(strategy RedactionStrategy) *Config {
	c.Strategy = strategy
	return c
}

// WithRegions sets the enabled regions
func (c *Config) WithRegions(regions ...Region) *Config {
	c.Regions = regions
	return c
}

// WithPartialMasking configures partial masking parameters
func (c *Config) WithPartialMasking(maskChar rune, keepLeft, keepRight int) *Config {
	c.PartialMaskChar = maskChar
	c.PartialKeepLeft = keepLeft
	c.PartialKeepRight = keepRight
	return c
}
