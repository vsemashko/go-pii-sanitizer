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

	// Input validation (v1.1.0+)
	// MaxFieldLength limits individual field value length (0 = unlimited, default: 0)
	// Oversized values are truncated before pattern matching for safety
	MaxFieldLength int

	// MaxContentLength limits total content size to scan (0 = unlimited, default: 0)
	// Prevents regex DOS on extremely large inputs
	MaxContentLength int

	// Observability (v1.1.0+)
	// Metrics is an optional metrics collector for tracking sanitization operations
	// If nil, metrics collection is disabled (default)
	Metrics MetricsCollector

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
		MaxFieldLength:        0,   // 0 = unlimited
		MaxContentLength:      0,   // 0 = unlimited
		Metrics:               nil, // nil = metrics disabled
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

// WithMaxFieldLength sets the maximum field length (v1.1.0+)
// Values longer than this will be truncated before pattern matching.
// Use 0 for unlimited (default).
//
// Example:
//
//	config := NewDefaultConfig().WithMaxFieldLength(10000) // 10KB limit
func (c *Config) WithMaxFieldLength(length int) *Config {
	c.MaxFieldLength = length
	return c
}

// WithMaxContentLength sets the maximum content length to scan (v1.1.0+)
// Prevents regex DOS on extremely large inputs.
// Use 0 for unlimited (default).
//
// Example:
//
//	config := NewDefaultConfig().WithMaxContentLength(100000) // 100KB limit
func (c *Config) WithMaxContentLength(length int) *Config {
	c.MaxContentLength = length
	return c
}

// WithMetrics sets the metrics collector (v1.1.0+)
// Pass nil to disable metrics collection (default).
//
// Example:
//
//	metrics := &MyMetrics{}
//	config := NewDefaultConfig().WithMetrics(metrics)
func (c *Config) WithMetrics(metrics MetricsCollector) *Config {
	c.Metrics = metrics
	return c
}

// Validate checks if the configuration is valid
// Returns an error if any configuration values are invalid
func (c *Config) Validate() error {
	if len(c.Regions) == 0 {
		return &ConfigValidationError{Field: "Regions", Message: "at least one region must be enabled"}
	}

	if c.PartialKeepLeft < 0 {
		return &ConfigValidationError{Field: "PartialKeepLeft", Message: "must be non-negative"}
	}

	if c.PartialKeepRight < 0 {
		return &ConfigValidationError{Field: "PartialKeepRight", Message: "must be non-negative"}
	}

	if c.MaxDepth < 1 {
		return &ConfigValidationError{Field: "MaxDepth", Message: "must be at least 1"}
	}

	if c.MaxDepth > 100 {
		return &ConfigValidationError{Field: "MaxDepth", Message: "must be at most 100 to prevent stack overflow"}
	}

	if c.MaxFieldLength < 0 {
		return &ConfigValidationError{Field: "MaxFieldLength", Message: "must be non-negative"}
	}

	if c.MaxContentLength < 0 {
		return &ConfigValidationError{Field: "MaxContentLength", Message: "must be non-negative"}
	}

	return nil
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Field   string
	Message string
}

func (e *ConfigValidationError) Error() string {
	return "config validation error: " + e.Field + " - " + e.Message
}
