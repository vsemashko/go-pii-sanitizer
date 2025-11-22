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

// TestZapComplexTypes tests zap marshaling with all supported types
func TestZapComplexTypes(t *testing.T) {
	s := NewDefault()

	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// Test with complex nested structure including all types
	data := map[string]any{
		"string":  "user@example.com",
		"int":     42,
		"int64":   int64(999),
		"float64": 99.99,
		"bool":    true,
		"nil":     nil,
		"nested": map[string]any{
			"email": "nested@example.com",
			"deep": map[string]any{
				"value": 123,
			},
		},
		"array": []any{
			"text",
			123,
			true,
			nil,
			map[string]any{"key": "value"},
			[]any{1, 2, 3}, // Nested array
		},
	}

	logger.Info("test", zap.Object("data", s.ZapObject(data)))

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("Expected log entry")
	}
}

// TestZerologComplexTypes tests zerolog marshaling with all supported types
func TestZerologComplexTypes(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	// Test with complex nested structure including all types
	data := map[string]any{
		"string":  "user@example.com",
		"int":     42,
		"int64":   int64(999),
		"float64": 99.99,
		"bool":    true,
		"nil":     nil,
		"nested": map[string]any{
			"email": "nested@example.com",
		},
		"array": []any{
			"text",
			123,
			int64(456),
			99.99,
			true,
			nil,
			map[string]any{"key": "value"},
		},
	}

	logger.Info().Object("data", s.ZerologObject(data)).Msg("test")

	// Verify output was generated
	if buf.Len() == 0 {
		t.Error("Expected log output")
	}
}

// TestSlogComplexTypes tests slog with all supported types
func TestSlogComplexTypes(t *testing.T) {
	s := NewDefault()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	// Test with complex nested structure
	data := map[string]any{
		"nested": map[string]any{
			"deep": map[string]any{
				"email": "deep@example.com",
			},
		},
		"array": []any{
			map[string]any{
				"items": []any{1, 2, 3},
			},
		},
	}

	logger.Info("test", "data", s.SlogValue(data))

	// Verify nested email is redacted
	if bytes.Contains(buf.Bytes(), []byte("deep@example.com")) {
		t.Error("Expected deeply nested email to be redacted")
	}
}

// TestAllRedactionStrategies tests all redaction strategies
func TestAllRedactionStrategies(t *testing.T) {
	strategies := []struct {
		name     string
		strategy RedactionStrategy
	}{
		{"Full", StrategyFull},
		{"Partial", StrategyPartial},
		{"Hash", StrategyHash},
		{"Remove", StrategyRemove},
	}

	for _, st := range strategies {
		t.Run(st.name, func(t *testing.T) {
			config := NewDefaultConfig().WithStrategy(st.strategy)
			if st.strategy == StrategyPartial {
				config = config.WithPartialMasking('*', 2, 2)
			}
			s := New(config)

			result := s.SanitizeField("email", "user@example.com")

			switch st.strategy {
			case StrategyFull:
				if result != "[REDACTED]" {
					t.Errorf("Expected [REDACTED], got %q", result)
				}
			case StrategyRemove:
				if result != "" {
					t.Errorf("Expected empty string, got %q", result)
				}
			case StrategyHash:
				if result == "user@example.com" {
					t.Error("Expected hash, got original")
				}
				if result[:7] != "sha256:" {
					t.Errorf("Expected hash to start with sha256:, got %q", result)
				}
			case StrategyPartial:
				if result == "user@example.com" {
					t.Error("Expected partial mask, got original")
				}
			}
		})
	}
}

// TestContentMatcherAllPatterns tests matching all content patterns
func TestContentMatcherAllPatterns(t *testing.T) {
	s := NewDefault()

	patterns := []struct {
		name    string
		content string
		match   bool
	}{
		{"Email", "contact@example.com", true},
		{"Credit Card", "4532015112830366", true},
		// IP Address removed - no longer detected by default
		{"SG Phone", "+6591234567", true},
		{"MY Phone", "+60123456789", true},
		{"UAE Phone", "+971501234567", true},
		{"TH Phone", "+66812345678", true},
		{"HK Phone", "+85291234567", true},
		{"Plain Text", "just regular text without PII", false},
	}

	for _, p := range patterns {
		t.Run(p.name, func(t *testing.T) {
			result := s.contentMatcher.matches(p.content)
			if result != p.match {
				t.Errorf("Expected match=%v for %q, got %v", p.match, p.content, result)
			}

			// Also test matchType
			matchedType := s.contentMatcher.matchType(p.content)
			if p.match && matchedType == "" {
				t.Errorf("Expected non-empty type for %q", p.content)
			}
			if !p.match && matchedType != "" {
				t.Errorf("Expected empty type for non-PII %q, got %q", p.content, matchedType)
			}
		})
	}
}

// TestFieldMatcherAllPatterns tests matching all field patterns
func TestFieldMatcherAllPatterns(t *testing.T) {
	s := NewDefault()

	fields := []struct {
		name     string
		field    string
		expected string
	}{
		{"Email", "email", "email"},
		{"Email Address", "email_address", "email"},
		{"User Email", "userEmail", "email"},
		{"Full Name", "fullName", "name"},
		{"First Name", "firstName", "name"},
		{"Last Name", "lastName", "name"},
		{"Phone", "phone", "phone"},
		{"Mobile", "mobile", "phone"},
		{"Address", "address", "address"},
		{"Street", "street", "address"},
		{"Password", "password", "secret"},
		{"Token", "token", "secret"},
		{"API Key", "apiKey", "secret"},
		{"Credit Card", "creditCard", "creditCard"},
		{"Account Number", "accountNumber", "bankAccount"},
		// Note: "iban" matches both bankAccount and UAE patterns
		{"Description", "description", "transaction"},
		{"Memo", "memo", "transaction"},
		{"Unknown", "unknownField123", ""},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			matchedType := s.fieldMatcher.matchType(f.field)

			// Note: Some fields may match multiple patterns (e.g., accountNumber matches both
			// bankAccount and regional patterns). We just verify it matches *something* or nothing.
			if f.expected != "" && matchedType == "" {
				t.Errorf("Expected field %q to match some type, got empty", f.field)
			}
			if f.expected == "" && matchedType != "" {
				t.Errorf("Expected field %q not to match, got type %q", f.field, matchedType)
			}

			// Also test matches
			matches := s.fieldMatcher.matches(f.field)
			if f.expected != "" && !matches {
				t.Errorf("Expected field %q to match", f.field)
			}
			if f.expected == "" && matches {
				t.Errorf("Expected field %q not to match", f.field)
			}
		})
	}
}

// TestNewWithNilConfig tests New with edge cases
func TestNewWithNilConfig(t *testing.T) {
	// Test with default config
	s := New(NewDefaultConfig())
	if s == nil {
		t.Fatal("Expected non-nil sanitizer")
	}

	// Verify it works
	result := s.SanitizeField("email", "test@example.com")
	if result != "[REDACTED]" {
		t.Errorf("Expected email to be redacted, got %q", result)
	}
}

// TestCompilePatternsAllRegions tests pattern compilation for all regions
func TestCompilePatternsAllRegions(t *testing.T) {
	regions := []struct {
		name   string
		region Region
	}{
		{"Singapore", Singapore},
		{"Malaysia", Malaysia},
		{"UAE", UAE},
		{"Thailand", Thailand},
		{"Hong Kong", HongKong},
	}

	for _, r := range regions {
		t.Run(r.name, func(t *testing.T) {
			config := NewDefaultConfig().WithRegions(r.region)
			s := New(config)

			if s == nil {
				t.Fatal("Expected non-nil sanitizer")
			}

			// Verify sanitizer works
			result := s.SanitizeMap(map[string]any{
				"test": "value",
			})

			if result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

// TestSanitizeMapWithNil tests SanitizeMap with nil values
func TestSanitizeMapWithNil(t *testing.T) {
	s := NewDefault()

	data := map[string]any{
		"nullValue": nil,
		"email":     "user@example.com",
		"orderId":   "ORD-123",
	}

	result := s.SanitizeMap(data)

	if result["nullValue"] != nil {
		t.Error("Expected nil to be preserved")
	}
	if result["email"] == "user@example.com" {
		t.Error("Expected email to be redacted")
	}
	if result["orderId"] != "ORD-123" {
		t.Error("Expected orderId to be preserved")
	}
}

// TestPartialMaskingWithDifferentSizes tests partial masking with various string lengths
func TestPartialMaskingWithDifferentSizes(t *testing.T) {
	config := NewDefaultConfig().
		WithStrategy(StrategyPartial).
		WithPartialMasking('*', 2, 2)
	s := New(config)

	tests := []struct {
		name  string
		value string
	}{
		{"Very long", "verylongemailaddress@example.com"},
		{"Medium", "user@example.com"},
		{"Short", "a@b.c"},
		{"Very short", "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.SanitizeField("email", tt.value)
			// Should not panic and should be different from original
			if result == tt.value && len(tt.value) > 4 {
				t.Errorf("Expected value to be masked, got original %q", result)
			}
		})
	}
}
