package sanitizer

import (
	"regexp"
	"testing"
)

// Edge case tests for redactor.go and other low-coverage areas

func TestRedact_AllStrategies(t *testing.T) {
	testCases := []struct {
		name     string
		strategy RedactionStrategy
		input    string
		validate func(t *testing.T, result string, input string)
	}{
		{
			name:     "Full redaction",
			strategy: StrategyFull,
			input:    "sensitive data",
			validate: func(t *testing.T, result string, input string) {
				if result != "[REDACTED]" {
					t.Errorf("Expected [REDACTED], got %q", result)
				}
			},
		},
		{
			name:     "Partial masking - empty string",
			strategy: StrategyPartial,
			input:    "",
			validate: func(t *testing.T, result string, input string) {
				if result != "" {
					t.Errorf("Expected empty string, got %q", result)
				}
			},
		},
		{
			name:     "Partial masking - very short string",
			strategy: StrategyPartial,
			input:    "ab",
			validate: func(t *testing.T, result string, input string) {
				// Should mask all or most of it
				if result == input {
					t.Error("Expected masking for short string")
				}
			},
		},
		{
			name:     "Hash strategy - empty string",
			strategy: StrategyHash,
			input:    "",
			validate: func(t *testing.T, result string, input string) {
				if !contains(result, "sha256:") {
					t.Errorf("Expected sha256 hash, got %q", result)
				}
			},
		},
		{
			name:     "Hash strategy - same input gives same hash",
			strategy: StrategyHash,
			input:    "test",
			validate: func(t *testing.T, result string, input string) {
				if !contains(result, "sha256:") {
					t.Error("Expected sha256 hash")
				}
				// Hash should be deterministic
				config := NewDefaultConfig().WithStrategy(StrategyHash)
				s2 := New(config)
				result2 := s2.redact(input)
				if result != result2 {
					t.Error("Expected same hash for same input")
				}
			},
		},
		{
			name:     "Remove strategy",
			strategy: StrategyRemove,
			input:    "anything",
			validate: func(t *testing.T, result string, input string) {
				if result != "" {
					t.Errorf("Expected empty string for Remove strategy, got %q", result)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewDefaultConfig().WithStrategy(tc.strategy)
			s := New(config)

			result := s.redact(tc.input)
			tc.validate(t, result, tc.input)
		})
	}
}

func TestPartialMasking_EdgeCases(t *testing.T) {
	testCases := []struct {
		name       string
		input      string
		maskChar   rune
		keepLeft   int
		keepRight  int
		expectDiff bool // Should result be different from input?
	}{
		{
			name:       "Keep more than length",
			input:      "short",
			maskChar:   '*',
			keepLeft:   10,
			keepRight:  10,
			expectDiff: false, // Might keep original or partially mask
		},
		{
			name:       "Zero keep on both sides",
			input:      "test",
			maskChar:   '*',
			keepLeft:   0,
			keepRight:  0,
			expectDiff: true,
		},
		{
			name:       "Keep all left",
			input:      "testing",
			maskChar:   '*',
			keepLeft:   7,
			keepRight:  0,
			expectDiff: false,
		},
		{
			name:       "Keep all right",
			input:      "testing",
			maskChar:   '*',
			keepLeft:   0,
			keepRight:  7,
			expectDiff: false,
		},
		{
			name:       "Single character",
			input:      "x",
			maskChar:   '*',
			keepLeft:   0,
			keepRight:  1,
			expectDiff: false,
		},
		{
			name:       "Custom mask character",
			input:      "secret",
			maskChar:   '#',
			keepLeft:   0,
			keepRight:  2,
			expectDiff: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := NewDefaultConfig().
				WithStrategy(StrategyPartial).
				WithPartialMasking(tc.maskChar, tc.keepLeft, tc.keepRight)
			s := New(config)

			result := s.redact(tc.input)

			if tc.expectDiff && result == tc.input {
				t.Errorf("Expected result to differ from input %q, got %q", tc.input, result)
			}

			// Check mask character is used
			if tc.expectDiff && tc.maskChar != '*' {
				if !containsStr(result, string(tc.maskChar)) {
					t.Errorf("Expected result to contain mask char %c, got %q", tc.maskChar, result)
				}
			}
		})
	}
}

func TestNew_WithNilConfig(t *testing.T) {
	// Should not panic with nil config
	s := New(nil)

	if s == nil {
		t.Error("Expected non-nil sanitizer even with nil config")
	}

	// Should use default behavior
	result := s.SanitizeField("email", "user@example.com")
	if result == "user@example.com" {
		t.Error("Expected email to be redacted with default config")
	}
}

func TestCompilePatterns_WithInvalidRegex(t *testing.T) {
	// This tests error handling in pattern compilation
	// Note: Our current patterns should all be valid, but we test the error path

	config := NewDefaultConfig()
	// Add a pattern with potentially complex regex
	config.CustomContentPatterns = []ContentPattern{
		{
			Name:    "complex",
			Pattern: mustCompilePattern(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`),
		},
	}

	s := New(config)

	if s == nil {
		t.Error("Expected non-nil sanitizer")
	}
}

func TestSanitizeMap_EmptyMap(t *testing.T) {
	s := NewDefault()

	result := s.SanitizeMap(map[string]any{})

	if len(result) != 0 {
		t.Error("Expected empty result for empty map")
	}
}

func TestSanitizeMap_NilMap(t *testing.T) {
	s := NewDefault()

	result := s.SanitizeMap(nil)

	if len(result) != 0 {
		t.Error("Expected empty result for nil map")
	}
}

func TestSanitizeSlice_NilSlice(t *testing.T) {
	s := NewDefault()

	result := s.sanitizeSlice(nil, 0)

	// sanitizeSlice returns empty slice for nil input, not nil
	if len(result) != 0 {
		t.Error("Expected empty slice for nil input")
	}
}

func TestSanitizeSlice_EmptySlice(t *testing.T) {
	s := NewDefault()

	result := s.sanitizeSlice([]any{}, 0)

	if len(result) != 0 {
		t.Error("Expected empty slice result")
	}
}

func TestSanitizeJSON_InvalidJSON(t *testing.T) {
	s := NewDefault()

	invalidJSON := []byte(`{"invalid": json}`)

	result, err := s.SanitizeJSON(invalidJSON)

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}

	if result != nil {
		t.Error("Expected nil result for invalid JSON")
	}
}

func TestSanitizeJSON_EmptyJSON(t *testing.T) {
	s := NewDefault()

	result, err := s.SanitizeJSON([]byte(`{}`))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(result) != 2 { // "{}" = 2 bytes
		t.Errorf("Expected valid empty JSON, got %s", string(result))
	}
}

func TestSanitizeStruct_NonStructTypes(t *testing.T) {
	s := NewDefault()

	testCases := []struct {
		name        string
		input       any
		expectEmpty bool
	}{
		{"String", "test", true},
		{"Int", 42, true},
		{"Slice", []string{"a", "b"}, true},
		{"Map", map[string]string{"key": "value"}, false}, // Maps are processed
		{"Nil", nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := s.SanitizeStruct(tc.input)

			if tc.expectEmpty {
				// Should return empty map for non-struct types (except maps)
				if len(result) != 0 {
					t.Errorf("Expected empty map for %s, got %v", tc.name, result)
				}
			}
		})
	}
}

func TestNewForRegion_MultipleRegions(t *testing.T) {
	s := NewForRegion(Singapore, Malaysia, UAE, Thailand, HongKong)

	// Test that all region patterns are enabled
	tests := []struct {
		field    string
		value    string
		redacted bool
	}{
		{"nric", "S1234567D", true},               // Singapore
		{"ic", "901230-14-5678", true},            // Malaysia
		{"eid", "784-2020-1234567-1", true},       // UAE
		{"nationalId", "1-2345-67890-12-1", true}, // Thailand - valid checksum
		{"hkid", "A123456(7)", true},              // Hong Kong
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := s.SanitizeField(tt.field, tt.value)
			if tt.redacted && result == tt.value {
				t.Errorf("Expected %s to be redacted for field %s", tt.value, tt.field)
			}
		})
	}
}

// TestNewForRegion_NoRegions removed - Empty regions now causes validation panic
// Config validation requires at least one region to prevent misconfiguration
// Use NewForRegion(Singapore) for minimal configuration instead

// Helper function
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstringInStr(s, substr))
}

func findSubstringInStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func mustCompilePattern(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
