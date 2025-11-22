package sanitizer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// redact applies the configured redaction strategy to a value
func (s *Sanitizer) redact(value string) string {
	switch s.config.Strategy {
	case StrategyFull:
		return "[REDACTED]"
	case StrategyPartial:
		return s.partialMask(value)
	case StrategyHash:
		return s.hashValue(value)
	case StrategyRemove:
		return "" // Signal to remove field
	default:
		return "[REDACTED]"
	}
}

// partialMask partially masks a value, preserving some characters
func (s *Sanitizer) partialMask(value string) string {
	totalKeep := s.config.PartialKeepLeft + s.config.PartialKeepRight
	if len(value) <= totalKeep {
		// Too short to mask partially, redact fully with asterisks
		return strings.Repeat(string(s.config.PartialMaskChar), len(value))
	}

	// Use strings.Builder for efficient concatenation
	var builder strings.Builder
	maskedLength := len(value) - totalKeep
	builder.Grow(len(value)) // Preallocate exact capacity

	builder.WriteString(value[:s.config.PartialKeepLeft])
	for i := 0; i < maskedLength; i++ {
		builder.WriteRune(s.config.PartialMaskChar)
	}
	builder.WriteString(value[len(value)-s.config.PartialKeepRight:])

	return builder.String()
}

// hashValue creates a SHA256 hash of the value
// If a salt is configured, it is prepended to the value before hashing
func (s *Sanitizer) hashValue(value string) string {
	// Prepend salt if configured
	input := s.config.HashSalt + value
	h := sha256.Sum256([]byte(input))
	// Return first 16 characters of hex for brevity
	return "sha256:" + hex.EncodeToString(h[:8])
}
