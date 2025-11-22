package sanitizer

import (
	"regexp"
	"testing"
)

// Edge case tests for matcher.go to improve validator path coverage

func TestContentMatcher_WithValidator(t *testing.T) {
	// Create pattern with validator
	pattern := ContentPattern{
		Name:    "test_with_validator",
		Pattern: regexp.MustCompile(`\b\d{3}-\d{3}-\d{4}\b`),
		Validator: func(s string) bool {
			// Only accept if it starts with "555"
			return len(s) >= 3 && s[:3] == "555"
		},
	}

	config := NewDefaultConfig()
	config.CustomContentPatterns = []ContentPattern{pattern}
	s := New(config)

	tests := []struct {
		name          string
		content       string
		shouldMatch   bool
		shouldRedact  bool
	}{
		{
			name:          "Valid pattern with passing validator",
			content:       "Call me at 555-123-4567",
			shouldMatch:   true,
			shouldRedact:  true,
		},
		{
			name:          "Valid pattern with failing validator",
			content:       "Call me at 123-456-7890",
			shouldMatch:   false,
			shouldRedact:  false,
		},
		{
			name:          "Multiple matches, only one passes validator",
			content:       "Numbers: 123-456-7890 and 555-999-8888",
			shouldMatch:   true,
			shouldRedact:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField("message", tt.content)

			if tt.shouldRedact {
				if result == tt.content {
					t.Errorf("Expected content to be redacted, got %v", result)
				}
			} else {
				if result != tt.content {
					t.Errorf("Expected content to be preserved, got %v instead of %v", result, tt.content)
				}
			}
		})
	}
}

func TestContentMatcher_ValidatorRejectsAll(t *testing.T) {
	// Pattern with validator that always returns false
	pattern := ContentPattern{
		Name:    "always_reject",
		Pattern: regexp.MustCompile(`\d{3}`),
		Validator: func(s string) bool {
			return false // Always reject
		},
	}

	config := NewDefaultConfig()
	config.CustomContentPatterns = []ContentPattern{pattern}
	s := New(config)

	content := "Numbers: 123 456 789"
	result := s.SanitizeField("field", content)

	// Should not redact since validator rejects all matches
	if result != content {
		t.Errorf("Expected content to be preserved when validator rejects all, got %v", result)
	}
}

func TestContentMatcher_MultipleMatchesWithValidator(t *testing.T) {
	// Pattern that matches emails but only validates @example.com domain
	pattern := ContentPattern{
		Name:    "example_emails_only",
		Pattern: regexp.MustCompile(`[a-z]+@[a-z]+\.[a-z]+`),
		Validator: func(s string) bool {
			return len(s) > 12 && s[len(s)-12:] == "@example.com"
		},
	}

	config := NewDefaultConfig()
	config.CustomContentPatterns = []ContentPattern{pattern}
	s := New(config)

	tests := []struct {
		name         string
		content      string
		shouldRedact bool
	}{
		{
			name:         "Contains example.com email",
			content:      "Contact: user@example.com",
			shouldRedact: true,
		},
		{
			name:         "Contains other domain",
			content:      "Contact: user@other.com",
			shouldRedact: true, // Still redacted by default email pattern
		},
		{
			name:         "Multiple emails, one matches",
			content:      "Emails: user@other.com and admin@example.com",
			shouldRedact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField("contact", tt.content)

			if tt.shouldRedact {
				if result == tt.content {
					t.Error("Expected content to be redacted")
				}
			} else {
				if result != tt.content {
					t.Error("Expected content to be preserved")
				}
			}
		})
	}
}

func TestMatchType_WithValidator(t *testing.T) {
	// Test that matchType returns correct type when validator is used
	pattern := ContentPattern{
		Name:    "special_numbers",
		Pattern: regexp.MustCompile(`\b\d{4}\b`),
		Validator: func(s string) bool {
			// Only accept "1234"
			return s == "1234"
		},
	}

	config := NewDefaultConfig()
	config.CustomContentPatterns = []ContentPattern{pattern}
	s := New(config)

	// Test with matching content
	matchType := s.contentMatcher.matchType("The code is 1234")
	if matchType != "special_numbers" {
		t.Errorf("Expected match type 'special_numbers', got %v", matchType)
	}

	// Test with non-matching content (pattern matches but validator rejects)
	matchType = s.contentMatcher.matchType("The code is 5678")
	if matchType != "" {
		t.Errorf("Expected empty match type when validator rejects, got %v", matchType)
	}
}

func TestFieldMatcher_EdgeCases(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name      string
		fieldName string
		expected  string // Expected match type, empty if no match
	}{
		{"Empty field name", "", ""},
		{"Very long field name", "this_is_a_very_long_field_name_that_should_not_match_anything", ""},
		{"Special characters", "field@name#123", ""},
		{"Numbers only", "12345", ""},
		{"Underscore variations", "user__email", ""}, // Doesn't match exact pattern
		{"CamelCase variation", "userEmailAddress", ""}, // Doesn't match exact pattern
		{"Mixed case", "EmAiL", "email"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchType := s.fieldMatcher.matchType(tt.fieldName)
			if matchType != tt.expected {
				t.Errorf("Expected match type %q, got %q for field %q", tt.expected, matchType, tt.fieldName)
			}
		})
	}
}

func TestContentMatcher_NoPatterns(t *testing.T) {
	// Create sanitizer with no content patterns
	config := NewDefaultConfig()
	config.Regions = []Region{} // No regions = no regional patterns
	s := New(config)

	// Should still have common patterns, but test with content that won't match
	result := s.SanitizeField("field", "random text 12345")

	// Should be preserved since no patterns match
	if result == "[REDACTED]" {
		t.Error("Expected content to be preserved when no patterns match")
	}
}

func TestFieldMatcher_WithCustomPatterns(t *testing.T) {
	config := NewDefaultConfig()
	config.CustomFieldPatterns = map[string][]string{
		"internal_ref": {"internalRef", "internal_ref", "refCode"},
		"employee_id":  {"employeeId", "employee_id", "staffId"},
	}
	s := New(config)

	tests := []struct {
		fieldName string
		expected  string
	}{
		{"internalRef", "internal_ref"},
		{"internal_ref", "internal_ref"},
		{"refCode", "internal_ref"},
		{"employeeId", "employee_id"},
		{"staffId", "employee_id"},
		{"unknownField", ""},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			matchType := s.fieldMatcher.matchType(tt.fieldName)
			if matchType != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, matchType)
			}
		})
	}
}

func TestMatches_WithEmptyString(t *testing.T) {
	s := NewDefault()

	// Test with empty content
	result := s.contentMatcher.matches("")
	if result {
		t.Error("Expected no match for empty string")
	}
}

func TestMatches_WithVeryLongString(t *testing.T) {
	s := NewDefault()

	// Create a very long string with a valid email buried in it
	prefix := make([]byte, 5000)
	for i := range prefix {
		prefix[i] = 'a'
	}
	email := "user@example.com"
	suffix := make([]byte, 5000)
	for i := range suffix {
		suffix[i] = 'b'
	}
	content := string(prefix) + email + string(suffix)

	// Should still match
	result := s.contentMatcher.matches(content)
	if !result {
		t.Error("Expected match in very long string")
	}
}
