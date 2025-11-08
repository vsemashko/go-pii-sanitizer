package sanitizer

// Region represents a geographic region for PII pattern matching
type Region string

const (
	Singapore Region = "SG"
	Malaysia  Region = "MY"
	UAE       Region = "AE"
	Thailand  Region = "TH"
	HongKong  Region = "HK"
)

// RedactionStrategy defines how PII should be redacted
type RedactionStrategy string

const (
	StrategyFull    RedactionStrategy = "full"    // "[REDACTED]"
	StrategyPartial RedactionStrategy = "partial" // "****1234"
	StrategyHash    RedactionStrategy = "hash"    // "sha256:abc..."
	StrategyRemove  RedactionStrategy = "remove"  // Remove field entirely
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
