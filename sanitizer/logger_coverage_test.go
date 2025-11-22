package sanitizer

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/rs/zerolog"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// TestSlogNestedArrays tests slog with nested arrays
func TestSlogNestedArrays(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	data := map[string]any{
		"users": []any{
			map[string]any{
				"emails": []any{"user1@example.com", "user1-alt@example.com"},
			},
			map[string]any{
				"emails": []any{"user2@example.com"},
			},
		},
		"orderId": "ORD-123",
	}

	logger.Info("test", "data", s.SlogValue(data))

	// Verify emails are redacted
	if bytes.Contains(buf.Bytes(), []byte("user1@example.com")) {
		t.Error("Expected nested email to be redacted")
	}
	if !bytes.Contains(buf.Bytes(), []byte("ORD-123")) {
		t.Error("Expected orderId to be preserved")
	}
}

// TestSlogMixedNestedTypes tests slog with complex nested structures
func TestSlogMixedNestedTypes(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	data := map[string]any{
		"matrix": []any{
			[]any{1, 2, 3},
			[]any{4, 5, 6},
		},
		"mixed": []any{
			"text",
			123,
			true,
			map[string]any{"email": "test@example.com"},
		},
	}

	logger.Info("test", "data", s.SlogValue(data))

	// Verify email in nested structure is redacted
	if bytes.Contains(buf.Bytes(), []byte("test@example.com")) {
		t.Error("Expected nested email in array to be redacted")
	}
}

// TestZapNestedArrays tests zap with nested arrays
func TestZapNestedArrays(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	data := map[string]any{
		"users": []any{
			map[string]any{
				"tags":   []any{"premium", "verified"},
				"emails": []any{"user1@example.com"},
			},
		},
		"matrix": []any{
			[]any{1, 2},
			[]any{3, 4},
		},
		"orderId": "ORD-123",
	}

	logger.Info("test", zap.Object("data", s.ZapObject(data)))

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("Expected log entry")
	}

	output := entries[0].ContextMap()
	dataMap := output["data"].(map[string]any)

	// Verify nested emails are redacted
	users := dataMap["users"].([]any)
	user1 := users[0].(map[string]any)
	emails := user1["emails"].([]any)
	if emails[0] == "user1@example.com" {
		t.Error("Expected nested email in array to be redacted")
	}

	// Verify orderId is preserved
	if dataMap["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

// TestZerologNestedArrays tests zerolog with nested arrays
func TestZerologNestedArrays(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	data := map[string]any{
		"matrix": []any{
			[]any{1, 2, 3},
			[]any{map[string]any{"value": "test"}},
		},
		"users": []any{
			map[string]any{
				"emails": []any{"nested@example.com"},
			},
		},
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("test")

	// Verify nested email is redacted
	if bytes.Contains(buf.Bytes(), []byte("nested@example.com")) {
		t.Error("Expected nested email to be redacted")
	}
}

// TestZerologDict tests ZerologDict method
func TestZerologDict(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"email":   "user@example.com",
		"orderId": "ORD-123",
	}

	dict := s.ZerologDict(data)

	// Verify dict was created (just checking it doesn't panic)
	if dict == nil {
		t.Error("Expected non-nil dict")
	}
}

// TestMatchesEdgeCases tests edge cases for the matches method
func TestMatchesEdgeCases(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name    string
		content string
		match   bool
	}{
		{
			name:    "Empty string",
			content: "",
			match:   false,
		},
		{
			name:    "Very long string with PII",
			content: "This is a very long string with an email user@example.com somewhere in the middle and continues for a while with more text",
			match:   true,
		},
		{
			name:    "Multiple PIIs",
			content: "Email: user1@example.com, Phone: +6591234567, NRIC: S1234567D",
			match:   true,
		},
		{
			name:    "PII at start",
			content: "user@example.com is the contact",
			match:   true,
		},
		{
			name:    "PII at end",
			content: "Contact email: user@example.com",
			match:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.contentMatcher.matches(tt.content)
			if result != tt.match {
				t.Errorf("Expected match=%v for %q, got %v", tt.match, tt.content, result)
			}
		})
	}
}

// TestMatchTypeEdgeCases tests edge cases for matchType
func TestMatchTypeEdgeCases(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name     string
		field    string
		expected string
	}{
		{
			name:     "Empty field name",
			field:    "",
			expected: "",
		},
		{
			name:     "Very long field name",
			field:    "this_is_a_very_long_field_name_that_should_not_match_anything",
			expected: "",
		},
		{
			name:     "Special characters",
			field:    "field!@#$%",
			expected: "",
		},
		{
			name:     "Mixed case email",
			field:    "EmAiL_AdDrEsS",
			expected: "email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.fieldMatcher.matchType(tt.field)
			if result != tt.expected {
				t.Errorf("Expected type=%q for field %q, got %q", tt.expected, tt.field, result)
			}
		})
	}
}

// TestSanitizeStructEdgeCases tests edge cases for SanitizeStruct
func TestSanitizeStructEdgeCases(t *testing.T) {
	s := NewDefault()

	// Test with primitive types (not a struct)
	t.Run("Primitive int", func(t *testing.T) {
		result := s.SanitizeStruct(42)
		if len(result) != 0 {
			t.Error("Expected empty map for primitive type")
		}
	})

	t.Run("Primitive string", func(t *testing.T) {
		result := s.SanitizeStruct("test")
		if len(result) != 0 {
			t.Error("Expected empty map for primitive type")
		}
	})

	// Test with unmarshalable type
	t.Run("Channel type", func(t *testing.T) {
		ch := make(chan int)
		result := s.SanitizeStruct(ch)
		if len(result) != 0 {
			t.Error("Expected empty map for unmarshalable type")
		}
	})
}

// TestRedactionStrategyEdgeCases tests edge cases for different redaction strategies
func TestRedactionStrategyEdgeCases(t *testing.T) {
	// Test partial masking with very short strings
	t.Run("Partial masking - very short string", func(t *testing.T) {
		config := NewDefaultConfig().
			WithStrategy(StrategyPartial).
			WithPartialMasking('*', 2, 2)
		s := New(config)

		// String shorter than left+right
		result := s.SanitizeField("email", "a@b")
		// Should handle gracefully without panic
		if result == "a@b" {
			t.Error("Expected short string to be redacted")
		}
	})

	// Test hash strategy
	t.Run("Hash strategy - consistent hashing", func(t *testing.T) {
		config := NewDefaultConfig().WithStrategy(StrategyHash)
		s := New(config)

		result1 := s.SanitizeField("email", "user@example.com")
		result2 := s.SanitizeField("email", "user@example.com")

		if result1 != result2 {
			t.Error("Expected consistent hashing for same input")
		}

		if result1 == "user@example.com" {
			t.Error("Expected email to be hashed")
		}
	})

	// Test remove strategy
	t.Run("Remove strategy", func(t *testing.T) {
		config := NewDefaultConfig().WithStrategy(StrategyRemove)
		s := New(config)

		result := s.SanitizeField("email", "user@example.com")
		if result != "" {
			t.Errorf("Expected empty string with remove strategy, got %q", result)
		}
	})
}

// TestSanitizeSliceEdgeCases tests edge cases for slice sanitization
func TestSanitizeSliceEdgeCases(t *testing.T) {
	s := NewDefault()

	tests := []struct {
		name  string
		slice []any
	}{
		{
			name:  "Empty slice",
			slice: []any{},
		},
		{
			name: "Slice with nil",
			slice: []any{
				nil,
				"value",
				nil,
			},
		},
		{
			name: "Deeply nested slices",
			slice: []any{
				[]any{
					[]any{
						map[string]any{
							"email": "deep@example.com",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]any{
				"items": tt.slice,
			}
			result := s.SanitizeMap(data)
			// Just verify it doesn't panic
			if result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}
